from flask import Flask, render_template,jsonify, request, send_file, redirect, url_for
import kubernetes, json, urllib3, subprocess
from kubernetes.client import ApiClient
from kubernetes import client, config, utils
from kubernetes.stream import stream
from datetime import datetime
from time import sleep
from kubernetes.client.rest import ApiException
from code import *
#from remote_code import pod_list


app = Flask(__name__)
#app.config["DEBUG"] = True

# remote cluster config

#aToken = "eyJhbGciOiJSUzI1NiIsImtpZCI6ImgzZVhaOXpBeDUzaDZnR3l1dC1BRjAwb3ZHd0NzNjVVWjItZXREQmVfekUifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJkZWZhdWx0Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6InRlc3QtdXNlci10b2tlbiIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJ0ZXN0LXVzZXIiLCJrdWJlcm5ldGVzLmlvL3NlcnZpY2VhY2NvdW50L3NlcnZpY2UtYWNjb3VudC51aWQiOiJjM2M2Mjg4Yi04YzU5LTQ4ODMtODY2MC0xODk5ZTJiMDQ5NDIiLCJzdWIiOiJzeXN0ZW06c2VydmljZWFjY291bnQ6ZGVmYXVsdDp0ZXN0LXVzZXIifQ.NMooAbEJLfzYaSzzIdr3uW9iKSbf7PMoaKNf5Mln4yl-WyFmjB6y51j0TlvM_fbzN2YFXPVlpkURYbdaUYXVF6B1xFlIIsAKxTdWkoQA1hJANiV485uxcJQfiJ_j-pmhLFcmOFDAy7hZBJUm94OZb1JhoNDPKiwz7UCMcWmOPppu_5hZHOrPmvnrcB5Lk4evg54R32iLMz3nB8BVFWB-SP8r_jZnwbEos3fdxhp9g6QED3ZmIaWSTOjqqpge5jJm2s6WmJQiKZLqWJnIEknguW-R3MtBJZZhX8nbY5inNQXDijMgycRzWQQEKQbJ4BamJKm9tkFXXL_NZDFrPY4obA"
    # Create a configuration object
#aConfiguration = client.Configuration()

    # Specify the endpoint of your Kube cluster
#aConfiguration.host = "https://10.2.12.217:6443"

    # Security part.
    # In this simple example we are not going to verify the SSL certificate of
    # the remote cluster (for simplicity reason)
#aConfiguration.verify_ssl = False
    # Nevertheless if you want to do it you can with these 2 parameters
    # configuration.verify_ssl=True
    # ssl_ca_cert is the filepath to the file that contains the certificate.
    # configuration.ssl_ca_cert="certificate"
#urllib3.disable_warnings()
#aConfiguration.api_key = {"authorization": "Bearer " + aToken}

    # Create a ApiClient with our config
#aApiClient = client.ApiClient(aConfiguration)

    # Do calls
#v1 = client.CoreV1Api(aApiClient)

# *** local cluster config
#config.load_kube_config()
#v1 = client.CoreV1Api()
#v2 = ApiClient()
#ret = v1.list_pod_for_all_namespaces(watch='False')
#pod = []
#for p in ret.items:
#    pod.append(pod.status.pod_ip)
#    pod.append(p.metadata.name)
#    pod.append(pod.metadata.namespace)
#    pod.append(pod.spec.node_name)


#########

#commande = ['calicoctl', 'get', 'wep', '-o', 'json']
#resp = stream(v1.connect_get_namespaced_pod_exec, 'calicoctl', 'kube-system', command=commande, stderr=True, stdin=False, stdout=True, tty=False)
#x = resp
#x = x.replace("'", '"')
#j = json.loads(x)
#pods = []
#interfaces = []
#for i in j["items"]:
#    pods.append(i["spec"]["pod"])
#    interfaces.append(i["spec"]["interfaceName"])

#ziper = zip(pods, interfaces)
#dicto = dict(ziper)


########

#pod = v1.list_namespaced_pod(namespace='defaul', _preload_content=False)
#pod = str(pod)
#pod = pod.replace("'", '"')
#print(type(pod))
#print(pod)
#pod = v2.sanitize_for_serialization(pod)
#pod = json.dumps(pod)
#print(type(pod))
#pod = json.loads(pod)

###################

@app.route('/', methods=['GET', 'POST'])
def login():
    global v1
    if request.method == 'POST':
        if request.form.get('ip') == None:
            config.load_kube_config()
            #config.load_incluster_config()     #inside pod
            v1 = client.CoreV1Api()
            return redirect(url_for("pods"))
        else:
            ip = request.form.get('ip')
            port = request.form.get('port')
            aToken = request.form.get('token')
            #print("ip "+ip)
            #print("port: "+port)
            #print("token: "+aToken)

            
            # Create a configuration object
            aConfiguration = client.Configuration()

            # Specify the endpoint of your Kube cluster
            aConfiguration.host = f"https://{ip}:{port}"
            #print(aConfiguration.host)

            # Security part.
            # In this simple example we are not going to verify the SSL certificate of
            # the remote cluster (for simplicity reason)
            aConfiguration.verify_ssl = False
            urllib3.disable_warnings()
            aConfiguration.api_key = {"authorization": "Bearer " + aToken}

            # Create a ApiClient with our config
            aApiClient = client.ApiClient(aConfiguration)

            # Do calls
            
            v1 = client.CoreV1Api(aApiClient)


            return redirect(url_for("pods"))
            #return ip



    #return redirect(url_for('pods'))    
    return render_template('login.html')


@app.route('/describe', methods=['GET','POST'])
def description():

    #output = request.get_json()
    #print(output) # This is the output that was stored in the JSON within the browser
    #print(type(output))
    #result = json.loads(output) #this converts the json output to a python dictionary
    #print(result) # Printing the new dictionary

    #podName = str(result["podName"])
    #namespace = str(result["namespace"])
    #desc = pod_description(v1, podName, namespace)
    return render_template('home.html',)


@app.route('/pods', methods=['GET'])
def pods():
    #user_question = request.form['question']
    #print(user_question)
    #if request.method == 'POST':
     #   config.load_kube_config()
     #   v1 = client.CoreV1Api()
     #   nodes = v1.list_node()
    global v1
    #podNames, podNamespaces, podIPs, podNode = pod_list(v1)
    headings = ["Pod", "Namespace", "IP", "Node", "Status"]
    #print(type(headings))
    pods2 = (
            ("pod1", "namespace1", "ip1", "node1"),
            ("pod2", "namespace2", "ip2", "node2"),
            ("pod3", "namespace3", "ip3", "node3"))
    pods = pod_list(v1)
    #i = 1
    #numbers = []
    #for i in range(1, len(pods)):
    #    numbers.append(i)
    #    i = i+1

    #print(res1)
    #return jsonify({'response': user_question})
    return render_template('tablehtmljs.html', headings=headings, pods=pods)
    #return render_template('css-table-15/index.html', headings=headings, pods=pods)


    #xx = str(pod_description(v1, "web-test-pod", "default"))
    #return render_template('tablehtmljs.html', xx=xx)

#pcapfile = str()
@app.route('/test', methods=['POST'])
def test():
    global pcapfile
    output = request.get_json()
    print(output) # This is the output that was stored in the JSON within the browser
    print(type(output))
    result = json.loads(output) #this converts the json output to a python dictionary
    #print(result) # Printing the new dictionary
    #print(type(result))#this shows the json converted as a python dictionary
    #print("flask showing data")
    #print("podName: " + result["podName"])
    #print("podNode: " + result["podNode"])
    #print(type(result["podName"]))
    #choosen_pod(str(result["podName"]))
    #return str(result["podName"])
    podName = str(result["podName"])
    #podIp = str(result["podIp"])
    podNode = str(result["podNode"])

    create_pod(v1, podNode)     # --creating a tcpdump pod on target node--
    
    pcapfile = capture_traffic_pod(v1, podName)    # --traffic capture on target pod--
    
    #global pcapfile
    #pcapfile = store_pcap()
    print(pcapfile)
    #stop_capture(v1, pcapfile) 
    #return 
    #return redirect(url_for('downloadFile', name="app"))


@app.route('/stop', methods=['POST'])
def stop():
    global v1
    print("success")
    global pcapfile
    #output = request.get_json()
    #res = json.loads(output)
    print(pcapfile)
    #print(res)
    stop_capture(v1, pcapfile)


@app.route('/download')
def downloadFile ():
    global v1
    global pcapfile
    delete_tcpdump(v1)
    #print(choosen_pod)
    #pcap_file_name = "app.pcap"
    #stop_capture(v1, pcapfile)
    path = pcapfile
    return send_file(path, as_attachment=True)


if __name__ == '__main__':
    #print(type(pods))
    app.run(host='localhost', port=5000)
