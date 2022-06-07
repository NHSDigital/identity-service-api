var issuer = context.getVariable('accesstoken.id_token-issuer');
var idTokenIssuer = '';
var InvalidIdTokenIssuer = false;

if(issuer === null || issuer === '' ) {
    InvalidIdTokenIssuer = true;
} else if (issuer.includes('NHSIdentity') || issuer.includes('cis2-mock') || issuer.includes('secure')) {
    idTokenIssuer = 'nhs-cis2';
} else if (issuer.includes('signin.nhs.uk') || issuer.includes('login.nhs.uk')) {
    idTokenIssuer = 'nhs-login';
} else {
    InvalidIdTokenIssuer = true;
}

context.setVariable('idTokenIssuer', idTokenIssuer);
context.setVariable('InvalidIdTokenIssuer', InvalidIdTokenIssuer)