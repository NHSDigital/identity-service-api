# Changelog

## 2020-08-11
* Added `Simulated OAuth` as an authentication option for the api tests

## 2020-06-18
* Move release and pull request pipelines into source control

## 2020-05-26
* Additional template hooks to configure KVMs and Target Server

## 2020-05-15
* Created an api testing framework to help facilitate automation

## 2020-05-13
* Remove id_token from the /token endpoint
* Update the specification to include the refresh parameters

## 2020-05-12
* Remove the scope query parameter from the callback redirection (scope-less OAuth)

## 2020-05-04
* Add the /authorize and the /token endpoint to the specification

## 2020-04-23
* Client Applications no longer authenticate themselves with both HTTP Basic Auth headers *and* Client ID + Secret in form data during POSTs to `/token` endpoint - now just the latter.

## 2020-04-22
* Add step in pipeline to replace invalid characters in the branch name

## 2020-04-09
* Store the JWT from the IdP as an attribute of the generated OAuth token for later use/retrieval

## 2020-03-02
* Add `NHSD-Session-URID` header to specification.
* Rename `from_asid` header to `NHSD-ASID`
* New PDS sandbox search scenarios
* Updating `Name` prefixes and suffixes to be an array of string, not string
* Add dispensing doctor and medical appliance supplier extensions


## 2020-02-26
* Add a config for dependabot so that security updates are automatically merged

## 2020-02-24
* Hugely improved linting of source code
* New testing setup & approach to support e2e tests
* Updated CI to run regression tests
* API Proxy: Add `from_asid` header when communicating with `ig3` target endpoint
* API Proxy (ops): Deployment scripts and instructions now support 'personal' developer proxies

## 2020-02-17
* Add Apigee API Proxy definition to repository
* Make command to deploy API Proxy and Sandbox server
* Continuous integration task to deploy API Proxy

## 2020-02-13
* Fix caching process, which was breaking on master
* Auto-link JIRA tickets in pull requests

## 2020-02-12
* Cache libraries during builds
* Tag and release successful master builds, and upload release assets

## 2020-02-11
* Moved the CI/CD pipeline from circleci to github actions
* Fixed a bug in CI pipeline that stopped version being correctly calculated

## 2020-02-10
* Updated API spec search documentation

## 2020-02-06
* Updated API spec overview documentation to clarify FHIR extensions and other bits and bobs based on user feedback

## 2020-02-03
* Updated API spec to make description formats consistent
* Updated API spec to clarify meanings of nominated pharmacies and registered GPs

## 2020-01-31
* Updated pull request template
* Updated CONTRIBUTING.md
* Added a make target to update examples
* Removed a documentation reference to ods-site-code
* Changed API base URL
* Added a better example for address lines
* Removed ods-site-code as a possible value for code system to identify a nominated pharmacy on Patient.
* Fix some mistakes in the README that referred to a nonexistent directory: `publish` -> `build`

## 2020-01-30
* Added automatic version calculation
* `make publish` now adds version into output oas file
* Added automatic version tagging to CI pipeline
* Added changelog
