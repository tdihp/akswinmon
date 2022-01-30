import logging
import threading
from queue import Queue
from collections import namedtuple
import datetime
from copy import copy

from dateutil.tz import UTC
from kubernetes import client as kclient, config, watch
import urllib3
from azure.identity import DefaultAzureCredential
from azure.mgmt.compute import ComputeManagementClient
from azure.mgmt.core.tools import parse_resource_id, is_valid_resource_id


logger = logging.getLogger()

DETECTION_COMMAND = r'Select-String -Path C:\k\kubelet.err.log -SimpleMatch -Pattern "The virtual machine or container exited unexpectedly.: unknown" | Select-Object -First 1'
Context = namedtuple('Context', ['k8s_client', 'az_compute_client'])


def watch_crashloop():
    """a loop forever which reports node name for any observed pod crashloop event"""
    log = logger.getChild('watch_crashloop')
    v1 = kclient.CoreV1Api()
    w = watch.Watch()
    conn_config = {
        '_request_timeout': (5, 65),
        'timeout_seconds': 60,
    }
    while True:
        try:
            for item in w.stream(
                    v1.list_event_for_all_namespaces,
                    field_selector='involvedObject.kind=Pod',
                    resource_version=w.resource_version,
                    **conn_config):
                # log.debug('got item: %s', item)
                if item['type'] not in ('ADDED', 'MODIFIED'):
                    continue
                ev = item['object']
                # log.debug('got ev: %s', ev)
                if ev.reason != 'BackOff':
                    continue

                log.info('captured backoff NS:%s, Pod:%s, node:%s',
                    ev.involved_object.namespace, ev.involved_object.name,
                    ev.source.host)
                assert ev.source.component == 'kubelet'
                yield ev.source.host, ev.last_timestamp

        except urllib3.exceptions.ReadTimeoutError as exp:
            log.exception('timeout when trying to watch pods')
        except kclient.exceptions.ApiException as exc:
            if exc.status == 410:
                w.resource_version = None
                logger.debug('resetting resource_version')
            else:
                log.exception('unexpteded k8s err')
        except Exception:
            log.exception('unexpected failure when watching')


def is_resource_detail_vmss(resource_detail):
    """resource_detail is supplied by parse_resource_id"""
    return resource_detail.get('type') == 'virtualMachineScaleSets' \
        and resource_detail.get('resource_type') == 'virtualMachines'


def get_resource_detail(node):
    """only returns if it is a valid vmss detail, otherwise returns None to skip"""
    provider_id = node.spec.provider_id
    azure_resource_id = provider_id[len('azure://'):]
    if provider_id.startswith('azure://') and is_valid_resource_id(azure_resource_id):
        detail = parse_resource_id(azure_resource_id)
        return detail

    return None


def check_runcommand(
        az_compute_client, resource_group, vmss_name, instance_id,
        powershell_script, timeout=240):
    """runs a powershel command against vmss instance
    
    Returns true as long as stdout has content, and stderr is empty.
    if both stdout and stderr is empty, return False. 
    """
    log = logger.getChild('check_runcommand')
    command_spec = {
        'command_id': 'RunPowerShellScript',
        'script': [powershell_script],
    }
    poller = az_compute_client.virtual_machine_scale_set_vms.begin_run_command(
        resource_group, vmss_name, instance_id, command_spec)
    result = poller.result(timeout=timeout)
    if not result:
        raise TimeoutError('polling timed out when check comand for %s, %s, %s'
            % (resource_group, vmss_name, instance_id))

    if result.value[0].code != 'ComponentStatus/StdOut/succeeded':
        raise ValueError('runcommand failed for %s, %s, %s, result: %s'
            % (resource_group, vmss_name, instance_id, result))

    stdout_status, stderr_status = result.value
    assert stderr_status.code == 'ComponentStatus/StdErr/succeeded'
    if stderr_status.message.strip():
        raise ValueError('runcommand for %s, %s, %s got stderr %s'
            % (resource_group, vmss_name, instance_id, stderr_status.message))

    if stdout_status.message.strip():
        log.info(
            'got stdout for %s, %s, %s: %s',
            resource_group, vmss_name, instance_id, stdout_status.message)
        return True
    log.debug(
        'blank outcome for %s, %s, %s',
        resource_group, vmss_name, instance_id)
    return False


class Remediator(object):
    def __init__(self,
            node_label_selector='kubernetes.io/os=windows',
            powershell_script=DETECTION_COMMAND,
            condition_template=kclient.models.V1NodeCondition(
                type='MarkedUnhealthyByCustomer',
                reason='MarkedUnhealthyByCustomer',
                message='error detected',
                status='True',
            ),
        ):
        self.node_label_selector = node_label_selector
        self.powershell_script = powershell_script
        self.condition_template = condition_template
        self.logger = logger.getChild('Remediator')

    def find_node(self, ctx, node_name):
        """returns node or None (if not found)"""
        v1 = kclient.CoreV1Api(ctx.k8s_client)
        nodes = v1.list_node(
                label_selector=self.node_label_selector,
                field_selector='metadata.name=%s' % node_name,
                _request_timeout=5)
        nodes = nodes.items
        assert len(nodes) <= 1
        if nodes:
            node, = nodes
            return node

        return None

    def is_mitigation_applied(self, ctx, node):
        conditions = node.status.conditions or []
        return any(condition.type == self.condition_template.type
            for condition in conditions)

    def is_mitigation_needed(self, ctx, node):
        resource_detail = get_resource_detail(node)
        if not resource_detail:
            self.logger.warning(
                'Unable to identify Azure resource for node %s',
                node.metadata.name)
            return

        self.logger.debug('resource detail: %s', resource_detail)
        if not is_resource_detail_vmss(resource_detail):
            self.logger.warning('resource detail is not vmss, ignoring')
            return

        match = check_runcommand(ctx.az_compute_client,
            resource_detail['resource_group'],
            resource_detail['name'],
            resource_detail['resource_name'],
            self.powershell_script)

        return match

    def apply_mitigation(self, ctx, node):
        # note: it is required to get node content again before this
        if self.is_mitigation_applied(ctx, node):
            return

        v1 = kclient.CoreV1Api(ctx.k8s_client)
        condition = copy(self.condition_template)
        now = datetime.datetime.now(tz=UTC)
        condition.last_heartbeat_time = now
        condition.last_transistion_time = now
        patch = {'status': {'conditions': [self.condition_template]}}
        v1.patch_node_status(node.metadata.name, patch, _request_timeout=5)

    def remediate_node(self, ctx, node_name):
        log = self.logger.getChild('remediate_node(%s)' % node_name)
        node = self.find_node(ctx, node_name)
        if not node:
            log.info('node not found, ignored, potentially not matching label selector')
            return

        if self.is_mitigation_applied(ctx, node):
            log.info('already mitigated, ignored')
            return

        if not self.is_mitigation_needed(ctx, node):
            log.info('confirmed no need to mitigate')
            return

        log.info('symptom found, applying mitigation')
        node = self.find_node(ctx, node_name)
        if not node:
            log.info('node gone after check')
            return

        if self.is_mitigation_applied(ctx, node):
            log.info('seems mitigation applied but not by myself')
            return

        self.apply_mitigation(ctx, node)
        log.info('mitigation applied')

    def cleanup(self, ctx):
        """clear all nodes state"""
        v1 = kclient.CoreV1Api(ctx.k8s_client)
        node_list = v1.list_node(label_selector=self.node_label_selector)
        for node in node_list.items:
            patch = []
            for i, condition in enumerate(node.status.conditions):
                if condition.type == self.condition_template.type:
                    patch.append({'op': 'remove', 'path': '/status/conditions/%d' % i})
        if patch:
            v1.patch_node_status(node.metadata.name, patch)


def observer(queue, node_label_selector='kubernetes.io/os=windows', period=600,
        trace_back=300):
    log = logger.getChild('observer')
    checked = {}
    for node_name, t in watch_crashloop():
        log.debug('%s, %s' % (node_name, t))
        now = datetime.datetime.now(tz=UTC)
        if (now - t).total_seconds() > trace_back:
            logger.debug('ignoring old event')
            continue

        if node_name in checked:
            dt = (t - checked[node_name]).total_seconds()
            if dt < period:
                log.debug('ignoring node %s at %s as already observed at %s',
                        node_name, t, checked[node_name])
                continue

        checked[node_name] = t
        # start intervention task
        queue.put(node_name)


class Worker(threading.Thread):
    daemon = True
    name = 'worker'
    
    def __init__(self, queue, remediator, ctx, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.queue = queue
        self.remediator = remediator
        self.ctx = ctx

    def run(self, ):
        log = logger.getChild('worker(%d)' % self.ident)
        queue = self.queue
        ctx = self.ctx
        node_name = queue.get()
        try:
            self.remediator.remediate_node(ctx, node_name)
        except Exception as exc:
            log.exception('unexpected failure when remediating node %s', node_name)
        finally:
            queue.task_done()


def main():
    # logging.basicConfig(level=logging.DEBUG)
    import argparse
    parser = argparse.ArgumentParser(
        description='Adhoc monitoring script for aks Windows issue 282516757.')
    parser.add_argument(
        '-v', '--verbose', action='count', default=0,
        help='Increase verbosity. default verbosity is INFO')
    parser.add_argument(
        '-q', '--quiet', action='count', default=0,
        help='Decrease verbosity.')
    parser.add_argument('-w', '--workers', default=2, type=int,
        help='worker thread count (default 2)')
    parser.add_argument('-m', '--match', default=DETECTION_COMMAND,
        help='specify a custom matching script')
    parser.add_argument('--cleanup', action='store_true')
    parser.add_argument('--subscription',
        help='Azure subscription id that contains the VMs')
    args = parser.parse_args()
    verbosity = (2  - args.verbose + args.quiet) * 10
    logging.basicConfig(level=verbosity)
    config.load_config()
    if args.cleanup:
        ctx = Context(kclient.ApiClient(), None)
        Remediator(powershell_script=args.match).cleanup(ctx)
        return

    if not args.subscription:
        raise parser.error('"--subscription" is required')

    az_compute_client = ComputeManagementClient(
        subscription_id=args.subscription,
        credential=DefaultAzureCredential())
    ctx = Context(kclient.ApiClient(), az_compute_client)
    queue = Queue()
    workers = [Worker(queue, Remediator(powershell_script=args.match), ctx)
        for i in range(args.workers)]
    for worker in workers:
        worker.start()

    observer(queue)


if __name__ == '__main__':
    main()
