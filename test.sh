NS=gap-test-$(date +%s | tail -c 5)
kubectl create ns $NS

# impersonation (never validated)
kubectl -n $NS create rolebinding sa-view --clusterrole=view --serviceaccount=$NS:default
kubectl --as=system:serviceaccount:$NS:default -n $NS get pods

# exec after the 99 change
kubectl -n $NS run gp --image=busybox --restart=Never -- sleep 300
kubectl -n $NS wait --for=condition=Ready pod/gp --timeout=60s
kubectl -n $NS exec gp -- id
kubectl -n $NS logs gp                      # pods/log — should stay Read, not 99
kubectl -n $NS port-forward pod/gp 18080:80 & sleep 3; kill %1

# secret read paths
kubectl -n $NS create secret generic gs --from-literal=k=v
kubectl -n $NS get secret gs -o yaml
kubectl -n $NS get secrets

# RBAC write — highest-signal event type in k8s
kubectl -n $NS create role r1 --verb=get --resource=pods
kubectl -n $NS create rolebinding rb1 --role=r1 --serviceaccount=$NS:default

# denial
kubectl --as=system:serviceaccount:$NS:default -n kube-system get secrets

kubectl delete ns $NS --wait=false
echo "marker: $NS"