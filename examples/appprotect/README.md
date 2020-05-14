# Example

In this example we deploy the NGINX Plus Ingress controller with App-Protect, a simple web application and then configure load balancing for that application using the Ingress resource.

## Running the Example

## 1. Deploy the Ingress Controller

1. Follow the installation [instructions](../../docs/installation.md) to deploy the Ingress controller.

2. Save the public IP address of the Ingress controller into a shell variable:
    ```
    $ IC_IP=XXX.YYY.ZZZ.III
    ```
3. Save the HTTPS port of the Ingress controller into a shell variable:
    ```
    $ IC_HTTPS_PORT=<port number>
    ```

## 2. Deploy the Cafe Application

Create the coffee and the tea deployments and services:
```
$ kubectl create -f cafe.yaml
```

## 3. Configure Load Balancing

1. Create a secret with an SSL certificate and a key:
    ```
    $ kubectl create -f cafe-secret.yaml
    ```
2. Create the App-Protect policy and log configuration:
    ```
    kubectl create -f dataguard_alarm.yaml
    kubectl create -f logconf.yaml
    ```
3. Create an Ingress resource:
    ```
    $ kubectl create -f cafe-ingress.yaml
    ```
    Note the annotations to the ingress. They enable and configure App-Protect with the policy and log configuration created in the last step.

## 4. Test the Application

1. To access the application, curl the coffee and the tea services. We'll use ```curl```'s --insecure option to turn off certificate verification of our self-signed
certificate and the --resolve option to set the Host header of a request with ```cafe.example.com```
    
    To get coffee:
    ```
    $ curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/coffee --insecure
    Server address: 10.12.0.18:80
    Server name: coffee-7586895968-r26zn
    ...
    ```
    If your prefer tea:
    ```
    $ curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP https://cafe.example.com:$IC_HTTPS_PORT/tea --insecure
    Server address: 10.12.0.19:80
    Server name: tea-7cd44fcb4d-xfw2x
    ...
    ```
    Now, Let's try something suspicious:
   ```
    $ curl --resolve cafe.example.com:$IC_HTTPS_PORT:$IC_IP 'https://cafe.example.com:$IC_HTTPS_PORT/tea/<script>' --insecure
    <html><head><title>Request Rejected</title></head><body>
    ...
    ```    
    As You can see the suspicious request was blocked by App-Protect
    
1. You can view an NGINX status page, either stub_status for NGINX, or the Live Activity Monitoring Dashboard for NGINX Plus:
    1. Follow the [instructions](../../docs/installation.md#5-access-the-live-activity-monitoring-dashboard--stub_status-page) to access the status page.
    2. For NGINX Plus, If you go to the Upstream tab, you'll see: ![dashboard](dashboard.png)
