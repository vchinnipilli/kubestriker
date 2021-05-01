<h1 align="center">
  <br>
  <a href="https://github.com/vchinnipilli/kubestriker"><img align="center" src="https://raw.githubusercontent.com/vchinnipilli/kubestriker/master/media/kube-striker.png"  height="400" width="400"></a>
</h1>

<h4 align="center"> A Blazing fast Security Auditing tool for <a href="https://kubernetes.io/" target="_blank">kubernetes</a>!!</h4>

![Python](https://img.shields.io/badge/python-v3.0+-blue.svg?style=plastic)
![Dependencies](https://img.shields.io/badge/dependencies-up%20to%20date-brightgreen.svg?style=plastic)
![Contributions welcome](https://img.shields.io/badge/contributions-welcome-orange.svg?style=plastic)
[![GitHub Issues](https://img.shields.io/github/issues/vchinnipilli/kubestriker?style=plastic)](https://github.com/vchinnipilli/kubestrike/issues)
![Release](https://img.shields.io/github/release-date/vchinnipilli/kubestriker?style=plastic)
![Stars Badge](https://img.shields.io/github/stars/vchinnipilli/kubestriker?style=plastic)
![Last Commit Date](https://img.shields.io/github/last-commit/vchinnipilli/kubestriker?style=plastic)
[![Hits](https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2Fvchinnipilli%2Fkubestriker&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=Visitors&edge_flat=false)](https://hits.seeyoufarm.com)
[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg?style=plastic)](https://github.com/vchinnipilli/kubestriker)
[![made-with-python](https://img.shields.io/badge/Made%20with-Python-1f425f.svg?style=plastic)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-Apache_License_2.0-blue.svg?style=plastic)](https://opensource.org/licenses/Apache_License_2.0)

### Basic Overview

**Kubestriker** performs numerous in depth checks on kubernetes infra to identify the  **security misconfigurations** and challenges that devops engineers/developers are likely to encounter when using Kubernetes, especially in production and at scale.

**kubestriker** is Platform agnostic and works equally well across more than one platform such as self hosted [kubernetes](https://kubernetes.io/), [Amazon EKS](https://aws.amazon.com/eks), [Azure AKS](https://azure.microsoft.com/en-us/services/kubernetes-service/), [Google GKE](https://cloud.google.com/kubernetes-engine) etc.

<p align="center"> <img src="https://raw.githubusercontent.com/vchinnipilli/kubestriker/master/media/pip-install.gif" width="600" height="400"/> </p>


### Table of content

- [How To Install](#How-To-Install)
  - [Clone the repo and install](#Clone-the-repo-and-install)
  - [Install using pip](#Install-using-pip)
  - [How to spin up kubestriker container](#How-to-spin-up-kubestriker-container)
- [Types of Scans](#Types-of-Scans)
  - [Authenticated scans](#Authenticated-scans)
  - [Unauthenticated scans](#Unauthenticated-scans)
    - [Identifying an open Insecure port on kubernetes master node](#Identifying-an-open-Insecure-port-on-kubernetes-master-node)
    - [Identifying a worker Node with kubelet readwrite and readonly ports open](#Identifying-a-worker-Node-with-kubelet-readwrite-and-readonly-ports-open)
- [Current Capabilities](#Current-Capabilities)
- [Future improvements](#Future-improvements)
- [Suggestions](#Suggestions)
- [Contributors](#Contributors)
- [Statistics](#Statistics)
- [License](#License)
- [Support](#Support)
- [Find me here!! <img src="https://raw.githubusercontent.com/vchinnipilli/kubestriker/master/media/wave.gif" width="30px">](#Find-me-here-img-src%22httpsrawgithubusercontentcomvchinnipillikubestrikermastermediawavegif%22-width%2230px%22)


## How To Install

### Clone the repo and install

To install this tool or clone and run this application, you'll need [Git](https://git-scm.com), [python3](https://www.python.org/downloads/) and [pip](https://pypi.org/project/pip/)  installed on your computer. It is advised you install this tool in [virtual environment](https://virtualenv.pypa.io/en/latest/installation.html)

From your command line:

```bash

# Create python virtual environment
$ python3 -m venv env

# Activate python virtual environment
$ source env/bin/activate

# Clone this repository
$ git clone https://github.com/vchinnipilli/kubestriker.git

# Go into the repository
$ cd kubestriker

# Install dependencies
$ pip install -r requirements.txt

# Incase of prompt toolkit or selectmenu errors
$ pip install prompt-toolkit==1.0.15 
$ pip install -r requirements.txt

# Gearing up Kubestriker
$ python -m kubestriker

# Result will be generated in the current working directory with the name of the target
```

### Install using pip

To install and run this application, you'll need [pip](https://pypi.org/project/pip/) installed on your computer. From your command line:

```bash

# Create python virtual environment
$ python3 -m venv env

# Activate python virtual environment
$ source env/bin/activate

# Install using pip
$ pip install kubestriker

# Incase of prompt toolkit or selectmenu errors
$ pip install prompt-toolkit==1.0.15 
$ pip install kubestriker

# Gearing up Kubestriker
$ python -m kubestriker

# Result will be generated in the current working directory with the name of the target
```

### How to spin up kubestriker container

[Use this link to view the Kubestriker container latest releases](https://hub.docker.com/repository/docker/cloudsecguy/kubestriker)

```bash
# Spinning up the kubestriker Container
$ docker run -it --rm -v /Users/vasantchinnipilli/.kube/config:/root/.kube/config -v "$(pwd)":/kubestriker --name kubestriker cloudsecguy/kubestriker:v1.0.0

# Replace the user vasantchinnipilli above with your username or absolute path of kube config file
$ docker run -it --rm -v /Users/<yourusername>/.kube/config:/root/.kube/config -v "$(pwd)":/kubestriker --name kubestriker cloudsecguy/kubestriker:v1.0.0

# Gearing up Kubestriker
$ python -m kubestriker

# Result will be generated in the current working directory with the name of the target
```
<p align="center"> <img src="https://raw.githubusercontent.com/vchinnipilli/kubestriker/master/media/docker.gif" width="600" height="400"/> </p>

## Types of Scans

### Authenticated scans
**Authenticated scan** expects the user to have atleast **read-only** privileges and provide a token during the scan. please use the below provided links to create read-only users

[Create read-only user for Amazon eks](https://docs.aws.amazon.com/eks/latest/userguide/add-user-role.html)\
[Create read-only user for Azure aks](https://docs.microsoft.com/en-us/azure/aks/control-kubeconfig-access)\
[Create read-only user for Google gke](https://cloud.google.com/kubernetes-engine/docs/how-to/iam)\
[Create a subject using Role based access control](https://medium.com/@rschoening/read-only-access-to-kubernetes-cluster-fcf84670b698)

```bash
# To grab a token from eks cluster
$ aws eks get-token --cluster-name cluster-name --region ap-southeast-2

# To grab a token from aks cluster
$ az aks get-credentials --resource-group myResourceGroup --name myAKSCluster

# To grab a token from gke cluster
$ gcloud container clusters get-credentials CLUSTER_NAME --zone=COMPUTE_ZONE

# To grab a token from service account
$ kubectl -n namespace get secret serviceaccount-token -o jsonpath='{.data.token}'

# To grab a token from a pod directly or via command execution bug
$ cat /run/secrets/kubernetes.io/serviceaccount/token
```

### Unauthenticated scans
**Unauthenticated scan** will be successful incase of anonymous access is permitted on the target cluster

#### Identifying an open Insecure port on kubernetes master node
<p align="center"> <img src="https://raw.githubusercontent.com/vchinnipilli/kubestriker/master/media/insecure_port.gif" width="600" height="400"/> </p>

#### Identifying a worker Node with kubelet readwrite and readonly ports open
<p align="center"> <img src="https://raw.githubusercontent.com/vchinnipilli/kubestriker/master/media/node_scan.gif" width="600" height="400"/> </p>

## Current Capabilities

* Scans Self Managed and cloud provider managed kubernetes infra
* Reconnaissance phase checks for various services or open ports
* Performs automated scans incase of insecure, readwrite or readonly services are enabled
* Performs both authenticated scans and unauthenticated scans
* Scans for wide range of IAM Misconfigurations in the cluster
* Scans for wide range of Misconfigured containers
* Scans for wide range of Misconfigured Pod Security Policies
* Scans for wide range of Misconfigured Network policies
* Scans the privileges of a subject in the cluster
* Run commands on the containers and streams back the output
* Provides the endpoints of the misconfigured services
* Provides possible privilege escalation details
* Elaborative report with detailed explanation


## Future improvements

* Automated exploitation based on the issues identified
* api and cicd automation friendly
* A Decent FrontEnd to make the lives easier

## Suggestions

Kubestriker is an opensource and [emailware](https://en.wiktionary.org/wiki/emailware). Meaning, if you liked using this tool or it has helped you in any way or if you have any suggestions/improvements, I'd like you send me an email at <vchinnipilli@gmail.com> about anything you'd want to say about this tool. I'd really appreciate it!


## Contributors

## Statistics

<a href="https://github.com/vchinnipilli/kubestriker">
  <img align="center" src="https://github-readme-stats.vercel.app/api?username=kubestriker&orgs=vchinnipilli&show_icons=true&layout=compact" />
</a>
<a href="https://github.com/vchinnipilli/kubestriker">
  <img align="center" src="https://github-readme-stats.vercel.app/api/top-langs/?username=kubestriker&orgs=vchinnipilli&layout=compact" />
</a>

## License
**[Apache License 2.0](https://github.com/vchinnipilli/kubestriker/blob/master/LICENSE)**

##  Support
[vasant chinnipilli](https://cloudsecguy.dev) builds and maintains kubestriker to audit and secure kubernetes infrastructure. 

Start with [Documentation - will be available soon](https://cloudsecguy.dev) for quick tutorials and examples.

If you need direct support you can contact me at vchinnipilli@gmail.com.

## Find me here!! <img src="https://raw.githubusercontent.com/vchinnipilli/kubestriker/master/media/wave.gif" width="30px"> 
[![cloudsecguy.dev](https://img.shields.io/badge/-https://www.cloudsecguy.dev-brightgreen?style=plastic&label=web:&logoColor=white&link=https://www.cloudsecguy.dev/)](https://www.cloudsecguy.dev/)
[![Linkedin Badge](https://img.shields.io/badge/-vasantChinnipilli-blue?style=plastic&logo=Linkedin&logoColor=white&link=https://www.linkedin.com/in/vasantreddy/)](https://www.linkedin.com/in/vasantreddy/)
[![Instagram Badge](https://img.shields.io/badge/-vasantchinnipilli-orange?style=plastic&logo=instagram&logoColor=white&link=https://instagram.com/vasant_reddy/)](https://instagram.com/vasant_reddy)
[![Medium Badge](https://img.shields.io/badge/-@vasantchinnipilli-03a57a?style=plastic&labelColor=000000&logo=Medium&link=https://medium.com/@vasantkumarchinnipilli/)](https://medium.com/@vasantkumarchinnipilli)
[![Gmail Badge](https://img.shields.io/badge/-vchinnipilli@gmail.com-c14438?style=plastic&logo=Gmail&logoColor=white&link=mailto:vchinnipilli@gmail.com)](mailto:vchinnipilli@gmail.com)
