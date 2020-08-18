# Performance Testing

## Setup

### Pre-Requisites

* python 3.8
* [poetry](https://github.com/python-poetry/poetry)

### Install

* `poetry install`

## Configure

In order to use the Identity Service you need a *App* with access to an appropriate API Product. This will have a *Key* and *Secret*, and be configured with a *Callback URL*.

The association of App to *API Product* will determine the effective **Rate Limiting** in place when making calls to the Identity Service.

Configure by setting environment variables:

| Variable        | Description                                                  | Example                            |
| --------------- | ------------------------------------------------------------ | ---------------------------------- |
| `CALLBACK_URL`  | From App                                                     | https://example-app.com/callback   |
| `CLIENT_ID`     | From App                                                     | `wV0D06YOqyyyy2b98AwxxxxG4cpI1111` |
| `CLIENT_SECRET` | From App                                                     | `7voRLOLRNOPEIsUA`                 |
| `LOCUST_HOST`   | Hostname and scheme of the deployed identity service         | `https://int.api.service.nhs.uk`   |
| `NAMESPACE`     | OPTIONAL. For PR-Deployed (namespaced) proxies. Used to create the base path to the identity service, of the format `/oauth2-<NAMESPACE>` | `some-namespace`                   |

:bulb: Use [direnv](https://direnv.net/) for convenience.

## Run

1. `pyenv run locust -f  locustfile.py`
2. Use WebUI at http://localhost:8089/

:bulb: Use `--headless` switch to run from CLI

## Further Info

See locust configuration: https://docs.locust.io/en/stable/configuration.html
