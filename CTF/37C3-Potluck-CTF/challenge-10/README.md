# Challenges setup Hungry Helmsman

## Create a Kubernetes Cluster

You can create a Kubernetes using [kind](https://kind.sigs.k8s.io/) or [minikube](https://minikube.sigs.k8s.io/docs/start/). Both distros can run on your local machine, that you dont need to spend $$$ on the Cloud Kubernetes distros, but they also work!

## Install Challenge

Once your Cluster is up and running apply the resources.

```
kubectl apply -f challenge.yaml
kubectl apply -f user.yaml
```

Afterwards create the token for the ctf-player account.

```
kubectl create token ctf-player
```

The output should be a valid Kubenretes API token. You should use this token to talk to the API Server.


```
kubectl get pods --token <YOUR-TOKEN>

or

alias kubectl='kubectl --token <YOUR-TOKEN>'
```

Now you are ready to play the challenge.
