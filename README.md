# akswinmon

This controller watches pod crashloop for Windows nodes, and marks condition `MarkedUnhealthyByCustomer` whenever a powershell script shows match.

The default match command in Powershell is `Select-String -Path C:\k\kubelet.err.log -SimpleMatch -Pattern "The virtual machine or container exited unexpectedly.: unknown" | Select-Object -First 1`, Only windows VMSS nodes are possible to be marked.
