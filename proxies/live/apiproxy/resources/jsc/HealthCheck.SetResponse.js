const apiproxyRevision = context.getVariable('apiproxy.revision');

// Get Cis2 variables 
const cis2HealthcheckStatusCode = context.getVariable('cis2HealthcheckResponse.status.code');
const cis2HealthcheckRequestUrl = context.getVariable('cis2HealthCheckRequest.url');
const cis2HealthcheckFailed = context.getVariable("servicecallout.ServiceCallout.CallCis2HealthcheckEndpoint.failed");

// Get Nhs-Login variables 
const nhsLoginHealthchecktatusCode = context.getVariable('nhsLoginHealthcheckResponse.status.code');
const nhsLoginHealthcheckRequestUrl = context.getVariable('nhsLoginHealthCheckRequest.url');
const nhsLoginHealthcheckFailed = context.getVariable("servicecallout.ServiceCallout.CallNhsLoginHealthcheckEndpoint.failed");


function json_tryparse(raw) {
    try {
        return JSON.parse(raw);
    }
    catch (e) {
        return raw;
    }
}

const cis2HealthcheckContent = json_tryparse(context.getVariable('cis2HealthcheckResponse.content'));
const nhsLoginHealthcheckContent = json_tryparse(context.getVariable('nhsLoginHealthcheckResponse.content'));

const cis2HealthcheckStatus = (cis2HealthcheckStatusCode/100 === 2) ? "pass" : "fail";
const nhsLoginHealthcheckStatus = (nhsLoginHealthchecktatusCode/100 === 2) ? "pass" : "fail";

const cis2Timeout = (cis2HealthcheckStatusCode === null && HealthCheckFailed) ? "true" : "false";
const nhsLoginTimeout = (nhsLoginHealthchecktatusCode === null && HealthCheckFailed) ? "true" : "false";

let finalStatus;
if (cis2HealthcheckStatus === "pass" && nhsLoginHealthcheckStatus === "pass") {
    finalStatus = "pass";
} else if (cis2HealthcheckStatus !== nhsLoginHealthcheckStatus) {
    finalStatus = "warn";
} else {
    finalStatus = "fail";
}

const resp = {
    "status" : finalStatus,
    "version" : "{{ DEPLOYED_VERSION }}" ,
    "revision" : apiproxyRevision,
    "releaseId" : "{{ RELEASE_RELEASEID }}",
    "commitId": "{{ SOURCE_COMMIT_ID }}",
    "checks" : {
        "nhs-cis2" : {
            "status": cis2HealthcheckStatus,
            "timeout" : cis2Timeout,
            "responseCode" : cis2HealthcheckStatusCode,
            "outcome": cis2HealthcheckContent,
            "links" : {"self": cis2HealthcheckRequestUrl}
        },
        "nhs-login" : {
            "status": nhsLoginHealthcheckStatus,
            "timeout" : nhsLoginTimeout,
            "responseCode" : nhsLoginHealthchecktatusCode,
            "outcome": nhsLoginHealthcheckContent,
            "links" : {"self": nhsLoginHealthcheckRequestUrl}
        }
    }
};

context.setVariable("status.response", JSON.stringify(resp));
context.setVariable("response.content", JSON.stringify(resp));
context.setVariable("response.header.Content-Type", "application/json");