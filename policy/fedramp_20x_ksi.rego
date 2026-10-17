package main

import rego.v1

# 1. Enforce Rule MAS-CSO-IIR: All taggable created/modified resources MUST carry the MAS In-Scope tag
deny contains msg if {
    some rc in input.resource_changes
    rc.change.actions[_] in ["create", "update"]
    rc.change.after.tags_all != null
    tags := object.get(rc.change.after, "tags_all", {})
    object.get(tags, "FedRAMP-20x-MAS", "") != "In-Scope"
    msg := sprintf("[MAS-CSO-IIR FAIL] Resource '%s' is missing mandatory tag FedRAMP-20x-MAS='In-Scope'", [rc.address])
}

# 2. Enforce KSI-CMT-LMC (Redeploying vs Modifying): Block ECS ExecuteCommand interactive shells
deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_ecs_service"
    rc.change.after.enable_execute_command == true
    msg := sprintf("[KSI-CMT-LMC FAIL] ECS Service '%s' has enable_execute_command=true. Interactive shell modification is prohibited; redeploy immutable containers instead.", [rc.address])
}

# 3. Enforce KSI-CMT-LMC: Container images MUST use immutable @sha256 digests, not mutable ':latest' tags
deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_ecs_task_definition"
    is_string(rc.change.after.container_definitions)
    containers := json.unmarshal(rc.change.after.container_definitions)
    some c in containers
    not contains(c.image, "@sha256:")
    msg := sprintf("[KSI-CMT-LMC FAIL] Container '%s' in '%s' does not pin an immutable @sha256 digest.", [c.name, rc.address])
}

# 4. Enforce SC-28 / KSI-SVC: RDS instances MUST enable storage encryption with KMS CMK
deny contains msg if {
    some rc in input.resource_changes
    rc.type == "aws_db_instance"
    rc.change.after.storage_encrypted != true
    msg := sprintf("[SC-28 / KSI-SVC FAIL] RDS instance '%s' must have storage_encrypted = true.", [rc.address])
}

# 5. Enforce KSI-CNA-DFP (Least Privilege / AC-06): Prohibit wildcard Action '*' in IAM Role Policies
deny contains msg if {
    some rc in input.resource_changes
    rc.type in ["aws_iam_policy", "aws_iam_role_policy"]
    is_string(rc.change.after.policy)
    policy_doc := json.unmarshal(rc.change.after.policy)
    some stmt in policy_doc.Statement
    stmt.Effect == "Allow"
    stmt.Action == "*"
    msg := sprintf("[KSI-CNA-DFP FAIL] IAM Policy '%s' grants wildcard Action '*'. Least privilege required.", [rc.address])
}
