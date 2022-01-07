# OpenFaas Job Worker

OpenFaas Job Worker is a fork of project : OSCAR Worker - https://github.com/grycap/oscar-worker
Thanks to Sebástian Risco @srisco and  Alfonso Pérez @alpegon for the initial project.

As oscar-worker is no longer supported, i decide to fork it, and add few improvments :
 - OpenFaas Asynchronous Callback is now support using http header : X-Callback-Url. 
 - Labels and Annotations are injected in Jobs
 - Default-use Queue Name is now : job-faas-request, but it can be changed using env NATS_QUEUE setting.
 - openfaas-job-Worker run in openfaas namespace, jobs are create in namespace openfaas-job-fn
 - openfaas-job-Worker does not replace nats-queue-worker, openfaas default async still work.

OpenFaas Job Worker enables launching long-running functions as Kubernetes Jobs when `/async-function/` path is used to make requests, and if function was deployed with annotation:
com.openfaas.queue=job-faas-request

The goal is to ensure that each invocation has the specified resources and, furthermore, that functions can be executed in parallel depending on the resources available in the cluster.


## Configuration

You can configure the worker through environment variables. To modify the default values you can edit the `openfaas-job-worker-dep.yaml` file:

```yaml
...
        env:
        # Token to access the k8s API server (if not set reads the content of '/var/run/secrets/kubernetes.io/serviceaccount/token')  
        # - name: KUBE_TOKEN
        #   value: "xxx"
        - name: KUBERNETES_SERVICE_HOST
          value: "kubernetes.default"
        - name: KUBERNETES_SERVICE_PORT
          value: "443"
        - name: NATS_ADDRESS
          value: "nats.openfaas"
        - name: NATS_PORT
          value: "4222"
        - name: JOB_TTL_SECONDS_AFTER_FINISHED
          value: 60
        - name: JOB_BACKOFF_LIMIT
          value: 3
        - name: NATS_QUEUE
          value: "job-faas-request"

...
```

## Deployment

In order to deploy the OpenFaas Job Worker you need to have already installed OpenFaaS in the Kubernetes cluster. 

And create the required namespaces, RBAC and deployment:

```bash
kubectl apply -f yaml/openfaas-job-worker-namespaces.yaml
kubectl apply -f yaml/openfaas-job-worker-rbac.yaml
kubectl apply -f yaml/openfaas-job-worker-dep.yaml
```

## Secrets

If your OpenFaaS function have [secrets](https://docs.openfaas.com/reference/secrets/) defined, you must duplicate them to the `openfaas-job-fn` namespace for granting access to jobs:

```bash
kubectl get secret <SECRET_NAME> -n openfaas-fn -o yaml \
| sed s/"namespace: openfaas-fn"/"namespace: openfaas-job-fn"/\
| kubectl apply -n openfaas-job-fn -f -
```

## Logs

If you want to inspect worker's logs run:

```bash
kubectl logs deploy/openfaas-job-worker -n openfaas
```

To see specific function invocation logs, first get all pods of the `openfaas-job-fn` namespace and then query the one you want.
You have to specify the container Name by adding "-c" and your fuction name .

```bash
kubectl get pods -n openfaas-job-fn 
kubectl logs POD_NAME -n openfaas-job-fn -c FUNCTION_NAME
```

## Clear completed Jobs

Completed Jobs can be automatically deleted after finishing by enabling the `TTLAfterFinished` feature gate of Kubernetes versions >= `v1.12`. TTL Seconds to clean up Jobs can be configured through the `JOB_TTL_SECONDS_AFTER_FINISHED` environment variable of the worker.

To delete completed jobs manually, execute:

```bash
kubectl delete job $(kubectl get job -o=jsonpath='{.items[?(@.status.succeeded==1)].metadata.name}' -n openfaas-job-fn) -n openfaas-job-fn
```
