# Setup

## Install Warnet
The following process is adopted from the main [Warnet repository - Install Warnet](https://github.com/bitcoin-dev-project/warnet/blob/main/docs/install.md#install-warnet), following the install via pip method.

Clone this repository and from the root directory create a virtual environment and install Warnet:
```bash
git clone git@github.com:deadmanoz/warnet-replacement-cycling.git
cd warnet-replacement-cycling
python3 -m venv .venv
source .venv/bin/activate
pip install warnet
```

Warnet should now be available:
```bash
warnet
Usage: warnet [OPTIONS] COMMAND [ARGS]...

Options:
  --help  Show this message and exit.
...
```

## Install local dependencies
If you're using a cloud-based cluster, you can skip this step. These tools are required for running Warnet locally.
As per the [Warnet repository - Running Warnet Locally](https://github.com/bitcoin-dev-project/warnet/blob/main/docs/install.md#running-warnet-locally), the two options for running Warnet on a local Kubernetes cluster are Docker Desktop and Minikube:

> #### Docker Desktop
>
> [Docker desktop](https://www.docker.com/products/docker-desktop/) includes the docker engine itself and has an option to enable Kubernetes.
> Install it and enable Kubernetes in the option menu to start a cluster.
>
> #### Minikube
>
> Minikube requires a backend to run on with the supported backend being Docker.
>
> [Install Docker](https://docs.docker.com/engine/install/) first, and then proceed to [Install Minkube](https://minikube.sigs.k8s.io/docs/start/).
>
> After installing Minikube don't forget to start it with:
>
> ```shell
> minikube start
> ```
>
> Minikube has a [guide](https://kubernetes.io/docs/tutorials/hello-minikube/) on getting started which could be useful to validate that your minikube is running correctly.

## Install `kubectl` and `helm`
You'll need to have the `kubectl` and `helm` utilities installed to interact with your warnet cluster, regardless of whether you're using a cloud-based cluster or running Warnet locally. As per the [Warnet repository - install Warnet](https://github.com/bitcoin-dev-project/warnet/blob/main/docs/install.md#install-warnet), you can either install these using your operating system's package manager, a third party package manager like [Homebrew](https://brew.sh), or as binaries directly into the virtual environment by running `warnet setup`.

Check that these tools are correctly installed:
```bash
helm repo add examples https://helm.github.io/examples
helm install hello examples/hello-world
helm list
kubectl get pods
helm uninstall hello
```

## Checking the system configuration
Check your system configuration by running `warnet setup`. Example output:

```bash
warnet setup
                                                                    
                    ╭───────────────────────────╮                   
                    │  Welcome to Warnet Setup  │                   
                    ╰───────────────────────────╯                   
                                                                    
    Let's find out if your system has what it takes to run Warnet...

[?] Which platform would you like to use?:
   Minikube
 > Docker Desktop
   No Backend (Interacting with remote cluster, see `warnet auth --help`)

 ⭐️ Kubectl is satisfied: /opt/homebrew/bin/kubectl
 ⭐️ Helm is satisfied: /opt/homebrew/bin/helm
 ⭐️ Docker is satisfied: /usr/local/bin/docker
 ⭐️ Docker Desktop is satisfied: /usr/local/bin/docker
 ⭐️ Running Docker is satisfied: docker is running
 ⭐️ Kubernetes Running in Docker Desktop is satisfied:
	Kubernetes control plane is running at https://kubernetes.docker.internal:6443
	CoreDNS is running at https://kubernetes.docker.internal:6443/api/v1/namespaces/kube-system/services/kube-dns:dns/proxy

	To further debug and diagnose cluster problems, use 'kubectl cluster-info dump'.
 ⭐️ Warnet prerequisites look good.
```
