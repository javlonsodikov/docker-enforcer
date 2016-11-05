# docker_enforcer

## What for?
Docker enforcer audits containers running on a shared docker host. The aim of docker enforcer is to stop containers running on a single host, but not obeying rules configured by the host's administrator. These rules may restrict values used as container's parameters or values reported by container's performance metrics.
 
## How?
It's the easiest to run docker enforcer as a container. Before starting, pay attention to a few facts:
- Docker enforcer needs to be run as a privileged container and needs access to the docker socket.
- To keep the rule expressions as elastic as possible, they are directly stored as python code. This is a security risk, as any python code put into the rules file will be executed in a privileged container with access to the docker socket. Make sure that you rules file has restricted access and can be modified only by the root user.
- Docker enforcer can kill itself if you're not paying attention! You can protect it from stopping itself by using the white list contains rules to never kill containers named 'docker-enforcer' or 'docker_enforcer'.
- You can always exclude some containers from being killed due to rules evaluation by including their name in the white list.
 
### Preparing rules file
The rules file must include a python list of dictionaries, where each of the dictionaries is a single rule. The rule includes its name and a lambda function, which contains evaluation logic. 

Each of the rules is applied to data about each container. If any of the rules returns `True`, the container will be stopped (unless it's on the whitelist). Container's data includes the following properties:
- `position` - the sequence number of the container on the list of all containers, sorted by the start date,
- `params` - a dictionary of parameters used to start this container (for example with `docker run`),
- `metrics` - a dictionary of performance metrics reported by the docker daemon for the container.
 
The rules file is evaluated against all running containers each `CHECK_INTERVAL_S` seconds. Also, all rules are evaluated against a single container, when the container is being started.  
The very basic rules file, that doesn't stop any container looks like this (this is also the default list set):
```python
rules = [
    {
        "name": "always false",
        "rule": lambda c: False
    }
]
```

#### Sample rules - check configuration parameters
1. All containers must have memory limits set:
```python
rules = [
    {
        "name": "must have memory limit", 
        "rule": lambda c: c.params['HostConfig']['Memory'] > 0
    }
]    
```

1. Must have CPU quota set:
```python
rules = [
    {
        "name": "must have CPU limit",
        "rule": lambda c: c.params['HostConfig']['CpuQuota'] > 0 and c.params['HostConfig']['CpuPeriod'] > 0
    }
]    
```

1. Limit the number of containers running on the host:
```python
rules = [
    {
        rules = [{"name": "no more than 3",
        "rule": lambda c: c.position >= 3}]
    }
]    
```


#### Sample rules - check metrics
1. 
```python
rules = [
    {
        "name": "can't use over 1GB of RAM", 
        "rule": lambda c: c.metrics['memory_stats']['usage'] > 1 * 1024 ** 3        
    }
]    
```

You can see the full list of parameters available (except `position`) in the file [test_helpers.py](test_helpers.py).

### Running the container
Put your `rules.py` file into a directory, for example `rules_dir`, and run (minimal command):
```bash
docker run -d --name docker_enforcer -p 8888:8888 --privileged -v /rules_dir:/opt/docker_enforcer/rules -v /var/run:/var/run docker_enforcer:latest
```
After the successful run, a simple web API will be exposed to show current rules and status (see below). You can access `http://localhost:8888/rules` to see the list of rules configured. This should be in sync with the rules file you passed to the container.

Additionally, you configure the behavior by passing the following environment variables (using `-e KEY=VAL`) to the command above (values below are the defaults):
- "CHECK_INTERVAL_S=60" - how often the periodic check of containers against the rules is run 
- "DOCKER_SOCKET=unix:///var/run/docker.sock" -  path to the docker Unix socket, default should be OK in most cases
- "WHITE_LIST=docker-enforcer docker_enforcer" - space separated whitelist of container names; containers on the won't be stopped even if they break the rules
- "MODE=WARN" - by default docker enforcer runs in a 'WARN' mode, where violations of rules are logged, but the containers are never actually stopped; to enable containers stopping, set this to 'KILL' 
 
### Accessing data about running docker enforcer container
Docker enforcer exposes a simple HTTP API on the port 8888. This currently includes the following endpoints:
- `/` - shows statistics about containers stopped by docker enforcer,
- `/metrics` - exposes the number of containers stopped since launch in the [prometheus](https://prometheus.io/) data format.
- `/rules` - allows you to view the configured set of rules.
  