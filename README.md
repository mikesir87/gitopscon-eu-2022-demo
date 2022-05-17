## GitOpsCon EU 2022 Demo

This repository contains the source material for the talk I gave at GitOpsCon EU in 2022.

## Pre-reqs

Since the talk goes over various aspects of providing a platform for application teams, various components need to be up and running. Specifically, we need:

- [Flux](https://fluxcd.io) - needed to pull in team manifests
- [Gatekeeper](https://open-policy-agent.github.io/gatekeeper/website/docs/) - policy enforcement
- [Cert Manager](https://cert-manager.io) - used to issue certificates for applications
- An ingress controller (I'm using [Traefik](https://doc.traefik.io/traefik/))

To install everything at once, you can leverage the manifests in this repo (which deploys Flux and then uses `HelmRelease`s to deploy the other components):

```
kubectl apply -f ./setup
```

If you want to be a little more selective (you already have an Ingress controller running), pick and choose the components you need.