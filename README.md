# akswinmon

This controller watches pod crashloop for Windows nodes, and marks condition `MarkedUnhealthyByCustomer` whenever a powershell script shows match.

The default match command in Powershell is `Select-String -Path C:\k\kubelet.err.log -SimpleMatch -Pattern "The virtual machine or container exited unexpectedly.: unknown" | Select-Object -First 1`, Only windows VMSS nodes are possible to be marked.

## Install

The main aplication is controller.py, review [deploy_standalone.yaml] for a standalone installation, which only adds condition.

For a installation that includes mitigation with [draino](https://github.com/planetlabs/draino) (which drains the problematic node), see [deploy_draino.yaml].

## Dev / test

```
# pull the repository first
virtualenv env
source env/bin/activate
pip install -r requirements.txt
python controller.py --help
```

## Cleanup

controller.py offers cleanup option to remove the condition. run `python controller.py --cleanup` either in a dev environment, or in a working installation will clear the condition.
