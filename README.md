# fedcm-example
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)  
Experimental implementation of FedCM in Go  
:construction: **Note: This is not ready for production. It can be used only to test the behavior.** :construction:  
This simple implementation provides for developers to try out FedCM in their local environment.  

## Prerequisites

Some features depend on the version of Chrome. Therefore, please check the version of Chrome you are using and consider using Chrome Canary in some cases.  
For example, [the Button Mode API](https://developers.google.com/privacy-sandbox/blog/fedcm-chrome-125-updates) is starting an origin trial on desktop from Chrome 125. So now we need to use Chrome Canary to enable FedCmButtonMode.

## How to use

Run the IdP and RP server with one of the following commands:

```bash
# Use docker 
$ docker-compose build
$ docker-compose up -d

# No use of docker
rp $ go run main.go
idp $ go run main.go
```

Access to http://localhost:8001.

## References
- [Federated Credential Management API](https://developers.google.com/privacy-sandbox/3pcd/fedcm)
- [Federated Credential Management API developer guide](https://developers.google.com/privacy-sandbox/3pcd/fedcm-developer-guide)
