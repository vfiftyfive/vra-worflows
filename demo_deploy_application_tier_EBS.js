function isBlank(str) {
    return (!str || /^\s*$/.test(str));
}

function validateFilterEntry(etype, proto, portStart, portEnd)
{
    // Check for all null params
    if (!etype && !proto && !portStart && !portEnd)
    {
        System.log("APIC WFStub failed");
        throw new Error("APIC WFStub failed. Error: "
	                + "Missing mandatory params in Security Rules");
    }

    // Validate EtherType
    if (etype != "ip" && etype != "arp")
    {
        System.log("APIC WFStub failed");
        throw new Error("APIC WFStub failed. Error: "
	                + " Ethertypes other than ip, arp are not supported in vRA plugin."
	                + " For advanced policies please configure directly on APIC");
    }

    if (etype == "arp")
    {
        if (! isBlank(portStart) ||
            ! isBlank(portEnd) ||
            ! isBlank(proto))
        {
            System.log("Protocol & L4 ports not allowed for arp rule, please leave protocol & port info empty");
            throw new Error("Protocol & L4 ports not allowed for arp rule, please leave protocol & port info empty");
        }
    }
    // Validate Protocol types
    if(etype == "ip" &&
       proto != "tcp" &&
       proto != "udp" &&
       proto != "icmp" &&
       proto != "icmpv6")
    {
        System.log("APIC WFStub failed");
        throw new Error("APIC WFStub failed, Error: "
	                + " Protocol type other than (tcp,udp,icmp,icmpv6)are not supported in vRA plugin."
	                + " For advanced policies please configure directly on APIC");
    }

    if (proto == "icmp" ||
        proto == "icmpv6")
    {
        if ( ((portStart != "unspecified") && !isBlank(portStart)) ||
             ((portEnd != "unspecified") && ! isBlank(portEnd)))
        {
            System.log("L4 ports not allowed for icmp/icmpv6 rule, please leave port info empty or as unspecified");
            throw new Error("L4 ports not allowed for icmp/icmpv6 rule, please leave port info empty or as unspecified");
        }
    }
}
var vpcPlan = true;

var machine = payload.get('machine');
var machineProperties = machine.get('properties');
var machineId = machine.get('id');
//for each (var key in machineProperties.keys){
//	System.log('Property: ' + key + ' with value ' + machineProperties.get(key));
//}
var configSecPolicy = machineProperties.get('ExternalWFStubs.BuildingMachine.configSecPolicy');
System.log('Found Property configSecPolicy with value ' + configSecPolicy);
var epgName = machineProperties.get('ExternalWFStubs.BuildingMachine.epgName');
System.log('Found Property epgName with value ' + epgName);
var consumerL3ext = machineProperties.get('ExternalWFStubs.BuildingMachine.consumerL3ext');
System.log('Found Property consumerL3ext with value ' + consumerL3ext);
var l3extInstp = machineProperties.get('ExternalWFStubs.BuildingMachine.l3extInstp');
System.log('Found Property l3extInstp with value ' + l3extInstp);
var consumerEpg = machineProperties.get('ExternalWFStubs.BuildingMachine.consumerEpg');
System.log('Found Property consumerEpg with value ' + consumerEpg);
var appProfName = machineProperties.get("__Cafe.Root.Request.Id").slice(-5);
var secDstPortStart = machineProperties.get('ExternalWFStubs.BuildingMachine.secDstPortStart');
System.log('Found Property secDstPortStart with value ' + secDstPortStart);
var secDstPortEnd = machineProperties.get('ExternalWFStubs.BuildingMachine.secDstPortEnd');
System.log('Found Property secDstPortEnd with value ' + secDstPortEnd);
var secProtocol =  machineProperties.get('ExternalWFStubs.BuildingMachine.secProtocol');
System.log('Found Property secProtocol with value ' + secProtocol);
var secEtherType = machineProperties.get('ExternalWFStubs.BuildingMachine.secEtherType');
System.log('Found Property secEthertype with value ' + secEtherType);

var vCACVm = Server.findForType("vCAC:VirtualMachine", machineId);
var vCACHost = Server.findForType("vCAC:VCACHost", vCACVm.getEntity().hostId);
var vCACVmEntity = System.getModule("com.vmware.library.vcac").getVirtualMachineEntityFromId(vCACHost, machineId);
//vCACVmProperties = System.getModule("com.vmware.library.vcac").getPropertiesFromVirtualMachine(vCACHost,vCACVm);

var apicHelper = ApicActionUtils.getConfigHelper();

System.log("Stub - Getting APIC handle for " + apicName);
var handle = apicHelper.getApicHandle(apicName);

if (handle == null)
{
    System.log("got a NULL handle for " + apicName);
    actionResult = false;
    throw new Error("ERROR: Got a NULL handle for " + apicName);
}

System.log("Stub - Got a valid handle: " + handle);
System.log("VM Name is " + vCACVm.virtualMachineName);

if (configSecPolicy == 'true')
{
    // Validate security policy/filter parameters
    if (consumerEpg)
    {

        System.log("Calling - Add New Security Policy");
        System.log("Dst EPG: " + epgName);

	      // Check for if source and destination are same

		if (consumerEpg == epgName){
		    System.log("Add security policyset failed, tenant: " + tenantName);
		    throw new Error("Error: Source EPG " + epgName + " is same as "
		                + "destination EPG. Security is policy can be configured only between two different Networks/EPGs");
		}

        System.log("Validating sec entry# " +
                   secDstPortStart + ", " +
                   secDstPortEnd + ", " +
                   secProtocol + ", " +
                   secEtherType );

        validateFilterEntry(secEtherType, secProtocol, secDstPortStart, secDstPortEnd);

        System.log("Security policy parameters are valid");
    }
}

System.log("List of variables: handle=" + handle + " tenantName=" + tenantName + " appProfName=" + appProfName + " epgName=" + epgName + " bdName=" + bdName + " ctxName=" + ctxName + " epgSubnet=" + epgSubnet + " dvsName=" + dvsName + " vpcPlan=" + vpcPlan); 
var response = apichelper.addnetwork(handle,	// handle
                                    tenantname, 	// tenant
                                    appprofname,	// ap
                                    epgname,     // epg
                                    bdname,      // bd
                                    ctxname,     // ctx
                                    epgsubnet, 	// subnet
                                    dvsname,     // dvs/domain
                                    true,        // vmmdomain
                                    vpcplan,
                                    false,
                                    false,
                                    'vlan' );	// vpc network


if (response.result == "FAIL")
{
    System.log("Add Tenant network/EPG failed : " + epgName);
    throw new Error("Add Tenant network/EPG failed, Error code: "
	                + response.errorCode + " Error desc: " + response.errorDesc);
}
else
{
    System.log("Add tenant network/EPG succeeded, network: " + epgName);
    System.log("Output object: " + response.object);
}

if (configSecPolicy == 'true')
{
    if (consumerL3ext){
        var filterName = "flt_" + consumerL3ext + "_" + epgName;
		System.log('Name of filter is ' + filterName);
        var contractName = appProfName + "_" + consumerL3ext + "_" + epgName;
		System.log('Name of Contract is ' + contractName);
    System.getModule("com.cisco.nvermand").applyContract(apicName,
                                                        true,
                                                        false,
                                                        tenantName,
                                                        appProfName,
                                                        epgName,
                                                        "",
                                                        contractName,
                                                        consumerL3ext,
                                                        l3extInstp,
                                                        filterName,
                                                        secDstPortStart,
                                                        secDstPortEnd,
                                                        "unspecified",
                                                        "unspecified",
                                                        secProtocol,
                                                        secEtherType);
}

    else if (consumerEpg)
    {
        System.log("Calling - Add New Security Policy");
        System.log("Src EPG input: " + consumerEpg);
        System.log("Dst EPG: " + epgName);

		var filterName = "flt_" + consumerEpg + "_" + epgName;
		System.log('Name of filter is ' + filterName);
        var contractName = appProfName + "_" + consumerEpg + "_" + epgName;
		System.log('Name of Contract is ' + contractName);
		System.getModule("com.cisco.nvermand").applyContract(apicName,
															 false,
															 false,
															 tenantName,
															 appProfName,
															 epgName,
															 consumerEpg,
															 contractName,
															 "",
															 "",
															 filterName,
															 secDstPortStart,
															secDstPortEnd,
															 "unspecified",
															 "unspecified",
															 secProtocol,
															 secEtherType);

		if (response.result == "FAIL")
        {
            System.log("Add security policyset failed, tenant: " + tenantName);
            throw new Error("Add security policyset failed, Error code: "
                            + response.errorCode + " Error desc: " + response.errorDesc);
        }
        else
        {
            System.log("Add security policyset succeeded, tenant: " + tenantName);
        }
    }
}

var netName = tenantName + "|" + appProfName + "|" + epgName;

System.log("Network (port-group) name =  " + netName);

var propertyName = "VirtualMachine.Network0.Name";

var propertyIsHidden = false;
var propertyIsRuntime = false;
var propertyIsEncrypted = false;
var propertyValue = netName;
var doNotUpdate = false;

System.log("Updating the VM propertyName =  " + propertyName + " propertyValue = " + propertyValue); 
actionResult = System.getModule("com.vmware.library.vcac").addUpdatePropertyFromVirtualMachineEntity(vCACHost, vCACVmEntity, propertyName, propertyValue, propertyIsHidden, propertyIsRuntime, propertyIsEncrypted, doNotUpdate);

System.log("actionResult =  " + actionResult);
