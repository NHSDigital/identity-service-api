const allowedIPList = context.getVariable('identity-service-config.cis2.backchannel_allowed_ips');

context.setVariable('allowed_ip_1.address', allowedIPList[0].address);
context.setVariable('allowed_ip_1.mask', allowedIPList[0].mask);
context.setVariable('allowed_ip_2.address', allowedIPList[0].address);
context.setVariable('allowed_ip_2.mask', allowedIPList[0].mask);

if (allowedIPList.length === 2) {
    context.setVariable('allowed_ip_2.address', allowedIPList[1].address);
    context.setVariable('allowed_ip_2.mask', allowedIPList[1].mask);
}
