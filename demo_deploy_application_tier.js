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
vpcPlan = true;

vCACVmProperties = System.getModule("com.vmware.library.vcac").getPropertiesFromVirtualMachine(vCACHost,vCACVm);
appProfName = vCACVmProperties.get("__Cafe.Root.Request.Id");

 apicHelper = ApicActionUtils.getConfigHelper();

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

if (configSecPolicy == true)
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
response = apicHelper.addNetwork(handle,	// handle
                                 tenantName, 	// Tenant
                                 appProfName,	// AP
                                 epgName, 	// EPG
                                 bdName,     // BD
                                 ctxName,	// CTX
                                 epgSubnet, 	// Subnet
                                 dvsName,	// DVS/Domain
                                 true,          // vmmDomain
                                 vpcPlan,
								 false,
								 false,
								 'vlan');	// VPC network

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
	System.getModule("com.cisco.nvermand").intraEPGIsolate(apicName, tenantName, appProfName, epgName);
}

if (configSecPolicy == true)
{
    if (l3ConsumerEpg){
        var filterName = "flt_" + l3ConsumerEpg + "_" + epgName;
        var contractName = appProfName + "_" + l3ConsumerEpg + "_" + epgName;
        System.getModule("com.cisco.nvermand").applyContract(apicName, true, false, tenantName, appProfName, epgName, contractName, l3ConsumerEpg, l3extInstp, filterName, secDstPortStart,secDstPortEnd, "unspecified", "unspecified", secProtocol, secEtherType);
    }

    else if (consumerEpg)
    {
        System.log("Calling - Add New Security Policy");
        System.log("Src EPG input: " + consumerEpg);
        System.log("Dst EPG: " + epgName);

        var ruleSet = [];
        System.log("Processing sec entry# " +
                   secDstPortStart + ", " +
                   secDstPortEnd + ", " +
                   secProtocol + ", " +
                   secEtherType );

        var rule = new ApicSecurityRule();
        rule.dstFromPort = secDstPortStart;
        rule.dstToPort = secDstPortEnd;
        rule.protocol = secProtocol;
        rule.etherType = secEtherType;
        ruleSet.push(rule);

        response = apicHelper.addSecurityPolicySet(handle,	 // handle
                                                   tenantName,  // Tenant
                                                   appProfName,	 // AP
                                                   consumerEpg,	 // Src EPG
                                                   epgName,     // Dst EPG
                                                   ruleSet,     // Rule Set
                                                   true);	 // Create flag

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
