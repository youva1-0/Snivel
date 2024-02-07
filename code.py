import kubernetes, json, subprocess
from kubernetes import client, config, utils
from kubernetes.stream import stream
from kubernetes.client.rest import ApiException
from time import sleep
from front import *
from datetime import datetime
import sys
import yaml


def pod_description(v1, podName, namspace):
    descript = None 
    try:
         descript = v1.read_namespaced_pod(name='%s'%podName ,namespace='%s'%namspace)
    except ApiException as e:
        if e.status != 404:
            print("Unknown error: %s" % e)
            exit(1)
    
    #x = str(descript)
    #x = x.replace("'", '"')
    #description = json.loads(x)
    #print(description)
    return description


def node_list(instance):
    # listing nodes
    nodes = instance.list_node()
    print("listing nodes with ip and name")
    for node in nodes.items:
        print("%s\t%s" % (node.metadata.name, node.status.addresses[0].address))    

def pod_list(instance):
    # listing pods
    pods = instance.list_pod_for_all_namespaces(watch='False')
    podList = []
    allPods = []
    #podName = []
    #podNamespace = []
    #podIp = []
    #podNode = []
    print("listing pods with ip, name and namespace")
    for pod in pods.items:
        #print(
            #"%s\t%s\t%s\t%s" %
            #(pod.metadata.name,
            # pod.metadata.namespace,
            # pod.status.pod_ip,
            # pod.spec.node_name))
        podList.append(pod.metadata.name)
        podList.append(pod.metadata.namespace)
        podList.append(pod.status.pod_ip)
        podList.append(pod.spec.node_name)
        
        allPods.append(podList)
        podList = []
    return allPods

def get_tcpdump_ip(v1):
    res = v1.read_namespaced_pod(name='tcpdump-n', namespace='default')
    ip = res.status.pod_ip
    return str(ip)

pcapfile = "file.pcap"

def capture_traffic_pod(v1, podName):
    
    global pcapfile

    name = str(podName)
    now = datetime.now()
    #print("now =", now)
    interface = get_pod_interface(v1, name)
    # dd/mm/YY H:M:S
    dt_string = now.strftime("%d-%m-%Y-%H-%M-%S")
    #print("date and time =", dt_string)
    pcapfile = str(f'{name}-{dt_string}.pcap')

    print(pcapfile)
    print(type(pcapfile))
    print("%s %s"%(interface, pcapfile))
    inter = 'pcap.pcap'
    exec_command = [
            'tcpdump',
            '-i',
            '%s'%interface,
            '-w',
            'tmp/%s'%pcapfile
            #'touch','tmp/%s'%pcapfile
            ]
    
    
    #exec_command.insert(2,'%s'%interface)
    #exec_command.insert(4, 'tmp/%s'%pcapfile)

    resp = stream(v1.connect_get_namespaced_pod_exec,
                      'tcpdump-n',
                      'default',
                       command=exec_command,
                       stderr=True, stdin=False,
                       stdout=True, tty=False,
                       _preload_content=False
                       )

    #resp.run_forever(timeout=1)
    print("command executed")
    return pcapfile
    #print(resp)

def store_pcap():
    global pcapfile
    pcap_file = pcapfile
    return pcap_file

def stop_capture(v1, pcapfile):
    #global pcapfile
    #print(pcapfile)
    #v1 = client.CoreV1Api()
    exec_command = [
            'pkill',
            'tcpdump'
            #'&&',
            #'python3',
            #'-m',
            #'http.server'
            ]
    
    resp = stream(v1.connect_get_namespaced_pod_exec,
                      'tcpdump-n',
                      'default',
                      command=exec_command,
                      stderr=True, stdin=False,
                      stdout=True, tty=False,
                      _preload_content=False)
    #print(resp)
    #resp.run_forever(timeout=2)
    exec_command = [
            'python3',
            '-m',
            'http.server'
            ]
    resp = stream(v1.connect_get_namespaced_pod_exec,
                        'tcpdump-n',
                        'default',
                        command=exec_command,
                        stderr=True, stdin=False,
                        stdout=True, tty=False,
                        _preload_content=False)

    resp.run_forever(timeout=2)
    #pcap_file = store_pcap()
    #print(pcap_file)
    ip = f'{get_tcpdump_ip(v1)}:8000/tmp/{pcapfile}'
    print(ip)
    download_command = ['curl', '-O', ip]
    subprocess.call(download_command)


def create_pod(v1, nodeName):
    # creating a pod
    # still options to add
    k8s_client = client.ApiClient()
    resp = None
    
    #resp = v1.read_namespaced_pod(name='tcpdump-n', namespace='default')
    print("before resp")
    
    
    try:
         resp = v1.read_namespaced_pod(name='tcpdump-n' ,namespace='default')
    except ApiException as e:
        if e.status != 404:
            print("Unknown error: %s" % e)
            exit(1)
    
    if resp:
        print("pod already exists")
        #exit(1)

    elif not resp:
        # yaml.preserve_quotes = True
        with open('podcp.yml') as file:
            #data = yaml.full_load(fp)
            documents = yaml.full_load(file)

            for item, doc in documents.items():
                if item == 'spec':
                    if doc['nodeName']:
                        doc['nodeName'] = nodeName
                        print(doc['nodeName'])
                        #yaml.dump(documents, sys.stdout)
                        break

        with open("podcp.yml", "w") as f:
            yaml.dump(documents, f)

        # ********** creating a pod from yaml file **********
        yaml_file = 'podcp.yml' # path_to_yaml_file/file.yaml
        utils.create_from_yaml(k8s_client,yaml_file,verbose=True)
        # ***************************************************    
     
        while True:
            res = v1.read_namespaced_pod(name='tcpdump-n', namespace='default')
            if res.status.phase == 'Running':
                #res.run_forever(timeout=1)
                break
            sleep(5)

    print("done!")

        #try:
        #    resp = instance.read_namespaced_pod(name='%s'%podName ,namespace='default')
        #except ApiException as e:
        #    if e.status != 404:
        #        print("Unknown error: %s" % e)
        #        exit(1)
        #if resp:
        #    capture_traffic_pod(v1)

        #if not resp:
        #    print("Creating tcpdump pod ...")

        #    pod_manifest = {
        #    'apiVersion': 'v1',
        #    'kind': 'Pod',
        #    'metadata': {
        #        'name': 'tcpdump-n'
        #    },
        #    'spec': {
                #'volumes': {
                #    'name': 'volume',
                #    'hostPath': {
                #        'path': '/home/vagrant'
                #    }
                #},
        #        'nodeName': '%s'%nodeName,
        #        'hostNetwork': 'true',
        #        'containers': [{
        #            'image': 'royov/tcpdump-n',
        #            'name': 'tcpdump-n',
                    #'command':[
                     #   "/bin/sh",
                      #  "echo",
                    # "snivel created me!",
                    # "tcpdump",
                    # "-i",
                    # get_pod_interface() 
                 #]
                 #'volumeMounts': {
                 #    'mountPath': '/',
                 #    'name': 'volume'
                 #}
         #           }]
        #   }
     # }
     
    #v1.create_namespaced_pod(body=pod_manifest, namespace='default')
               
def delete_tcpdump(v1):
    api_response = v1.delete_namespaced_pod('tcpdump-n', 'default')

def get_pod_interface(v1, podName):
    name = podName
    # deploying calicoctl pod
    k8s_client = client.ApiClient()
    resp = None
    try:
        resp = v1.read_namespaced_pod(name='calicoctl', namespace='kube-system')

    except ApiException as e:
        if e.status != 404:
            print("Unknown error: %s" % e)
            exit(1)
    
    if not resp:
        print("Pod calicoctl does not exist. Creating it ...")
        yaml_file = 'calicoctl.yml' # path_to_yaml_file/file.yaml
        utils.create_from_yaml(k8s_client,yaml_file,verbose=True)
        
        while True:
            resp = v1.read_namespaced_pod(name='calicoctl', namespace='kube-system')
            if resp.status.phase == 'Running':
                #resp.run_forever(timeout=1)
                break
            sleep(5)
        return exec_calicoctl(v1, name)

    # Calling exec and waiting for response
    elif resp:
        return exec_calicoctl(v1, name)

def exec_calicoctl(v1, podName):
    exec_command = [
        'calicoctl',
        'get',
        'wep',
        '-A',
        '-o',
        'json']
    resp = stream(v1.connect_get_namespaced_pod_exec,
                'calicoctl',
                'kube-system',
                command=exec_command,
                stderr=True, stdin=False,
                stdout=True, tty=False)
    
    #resp.run_forever(timeout=1)
    #print("Response: " + resp)

    # converting output from str to json
    x = resp
    x = x.replace("'", '"')
    j = json.loads(x)
    #print(j)

     # defining pods and interfaces in separate lists
    pods = []
    interfaces = []
    for i in j["items"]:
        pods.append(i["spec"]["pod"])
        interfaces.append(i["spec"]["interfaceName"])
    
    # creating a dictionary from the two lists
    zip_iterator = zip(pods, interfaces)

    # Get pairs of elements
    pods_interfaces_dictionary = dict(zip_iterator)
    
    # Convert to dictionary
    #return pods_interfaces_dictionary
    
    x_pod = podName
    x_interface = pods_interfaces_dictionary[x_pod]
    # print(f"the interface of {x} is {x_interface})
    # x_interface will be passed as an argument to capture traffic ... 
    print(x_interface)
    return str(x_interface)

def choosen_pod(name):
    # this function must get it's data from the user interface
    # the user chooses a pod that he want to capture traffic from
    # the user interface sends the pod's name here 
    # this function collects the necessary informations to create a p-pod
    
    #print("")
    return name


def main():
 # remote cluster access   

 # ***************************************
 
# local cluster access 
    config.load_kube_config()
    v1 = client.CoreV1Api()
    #create_pod(v1)
   # pod_list(v1)
   # node_list(v1)
    
    # ***
    print(store_pcap())
    choice = input("""choose a number:
                   1. get nodes list
                    2. get pods list
                      3. get a pod's network interface 
                        4. create a pod:
                          5. exec into a pod\n""")
    if choice == '1':
        node_list(v1)
    elif choice == '2':
        pod_list(v1)
    elif choice == '3':
        get_pod_interface(v1, 'web-test-pod')
    elif choice == '4':
        create_pod(v1, "worker2")
    elif choice == '5':
        capture_traffic_pod(v1, 'web-test-pod')
        store_pcap()
        print(store_pcap())
    elif choice == '6':
        stop_capture(v1)
    elif choice == '7':
        get_tcpdump_ip(v1)
    elif choice =='8':
        pod_description(v1, "web-test-pod", "default")
    else: 
        exit()

if __name__ == '__main__':
    main()



