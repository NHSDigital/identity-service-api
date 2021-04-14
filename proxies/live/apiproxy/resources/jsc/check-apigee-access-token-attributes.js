var issuer = context.getVariable('accesstoken.id_token-issuer');
var idTokenIssuer = '';
var InvalidIdTokenIssuer = false;

if(issuer === null || issuer === '' ) {
    InvalidIdTokenIssuer = true;
} else if (issuer.includes('NHSIdentity')|| issuer.includes('secure')) {
    idTokenIssuer = 'nhsCis2'; 
} else if (issuer.includes('signin.nhs.uk') || issuer.includes('login.nhs.uk')) {
    idTokenIssuer = 'nhsLogin';
} else {
    InvalidIdTokenIssuer = true;
}

context.setVariable('idTokenIssuer', idTokenIssuer);
context.setVariable('InvalidIdTokenIssuer', InvalidIdTokenIssuer)