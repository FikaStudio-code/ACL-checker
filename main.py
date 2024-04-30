import json

"""TODO
- delete matched
- www <-> 80 translate
- gt
"""

CONDITION = dict()
ACL = list()

def main():
    get_condition()
    get_acl()
    result = check_acl()

    if result[0]:
        print("Hit a policy!")
        print(json.dumps(result[1], indent = 4))
    else:
        print("no policy hit...")

def get_condition():
    global CONDITION
    with open("condition.json", "r") as f:
        CONDITION = json.loads(f.read())

def get_acl():
    global ACL
    with open("acl.txt", "r") as f:
        ACL = f.read().split("\n")

def parse_policy(policy):
    policy_dict = dict()
    action = policy.pop(0)
    protocol = policy.pop(0)
    sender_subnet = ""
    sender_port = ""
    destination_subnet = ""
    destination_port = ""

    p = policy.pop(0)
    if p == "any":
        sender = "any"
    elif p == "host":
        sender = policy.pop(0)
    else:
        sender = p
        sender_subnet = policy.pop(0)

    q = policy.pop(0)
    if q == "eq":
        sender_port = policy.pop(0)
    elif q == "range":
        q2 = policy.pop(0)
        q3 = policy.pop(0)
        sender_port = q2 + "-" + q3
    elif q == "any":
        destination = "any"
    elif q == "host":
        destination = policy.pop(0)
    else:
        destination = q
        destination_subnet = policy.pop(0)

    if not protocol == "ip":
        r = policy.pop(0)
        if r == "eq":
            destination_port = policy.pop(0)
        elif r == "range":
            r2 = policy.pop(0)
            r3 = policy.pop(0)
            destination_port = r2 + "-" + r3

    policy_dict = {
        "action": action,
        "protocol": protocol,
        "sender": sender,
        "sender_subnet": sender_subnet,
        "sender_port": sender_port,
        "destination": destination,
        "destination_subnet": destination_subnet,
        "destination_port": destination_port
    }

    print(json.dumps(policy_dict, indent = 4))
    return policy_dict

def check_acl():
    result = False
    hit_policy = dict()

    for i in ACL:
        p = i.split(" ")[2:]
        if p[-1] == "established":
            continue
        else:
            policy = parse_policy(p)
            flag = protocol_check(policy)
            print(flag)
            if not flag:
                continue
            flag = sender_check(policy)
            print(flag)
            if not flag:
                continue
            flag = sender_port_check(policy)
            print(flag)
            if not flag:
                continue
            flag = destination_check(policy)
            print(flag)
            if not flag:
                continue
            flag = destination_port_check(policy)
            print(flag)
            if not flag:
                continue
            result = True
            hit_policy = policy
            break

    return (result, hit_policy)


def protocol_check(policy):
    global CONDITION

    result = False

    if policy["protocol"] == "ip":
        result = True
    elif policy["protocol"] == CONDITION["protocol"]:
        result = True
    return result

def sender_check(policy):
    global CONDITION

    if policy["sender"] == "any":
        result = True
    elif policy["sender_subnet"]:
        subnet = list(map(lambda x: int(x) ^ 255, policy["sender_subnet"].split(".")))
        masked_sender = list(map(lambda x: int(x[0]) & x[1], zip(policy["sender"].split("."), subnet)))
        masked_from = list(map(lambda x: int(x[0]) & x[1], zip(CONDITION["from"].split("."), subnet)))
        result = masked_sender == masked_from
    else:
        result = policy["sender"] == CONDITION["from"]
    return result

def destination_check(policy):
    global CONDITION

    if policy["destination"] == "any":
        result = True
    elif policy["destination_subnet"]:
        subnet = list(map(lambda x: int(x) ^ 255, policy["destination_subnet"].split(".")))
        masked_sender = list(map(lambda x: int(x[0]) & x[1], zip(policy["destination"].split("."), subnet)))
        masked_from = list(map(lambda x: int(x[0]) & x[1], zip(CONDITION["destination"].split("."), subnet)))
        result = masked_sender == masked_from
    else:
        result = policy["destination"] == CONDITION["destination"]
    return result

def sender_port_check(policy):
    global CONDITION

    result = False

    if policy["sender_port"] == "":
        result = True
    elif policy["sender_port"] == CONDITION["from-port"]:
        result = True
    elif "-" in policy["sender_port"]:
        port_range = policy["sender_port"].split("-")
        if port_range[0] <= CONDITION["from-port"] and CONDITION["from-port"] <= port_range[1]:
            result = True
    return result

def destination_port_check(policy):
    global CONDITION

    result = False

    if policy["destination_port"] == "":
        result = True
    elif policy["destination_port"] == CONDITION["destination-port"]:
        result = True
    elif "-" in policy["destination_port"]:
        port_range = policy["destination_port"].split("-")
        if port_range[0] <= CONDITION["destination-port"] and CONDITION["destination-port"] <= port_range[1]:
            result = True
    return result

def test():
    sender = "192.168.1.65"
    subnet = "0.0.0.63"
    condition_from = "192.168.1.125"

    a = list(map(lambda x: int(x) ^ 255, subnet.split(".")))

    b = list(map(lambda x: int(x[0]) & x[1], zip(sender.split("."), a)))
    c = list(map(lambda x: int(x[0]) & x[1], zip(condition_from.split("."), a)))

    print(b)
    print(c)
    print(b == c)

if __name__ == "__main__":
    main()