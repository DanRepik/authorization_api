from pulumi import automation as auto


def deploy_stack(project_name, stack_name, pulumi_program):
    stack = auto.create_or_select_stack(
        stack_name=stack_name,
        project_name=project_name,
        program=pulumi_program,
    )
    try:
        # Deploy the stack
        print("Deploying Pulumi stack...")
        up_result = stack.up()
        print(f"Deployment complete: {up_result.summary.resource_changes}")

        yield stack, up_result.outputs
    finally:
        print("Destroying Pulumi stack...")
        stack.destroy()
        print("Stack destroyed.")

        stack.workspace.remove_stack(stack_name)


def deploy_stack_no_teardown(project_name, stack_name, pulumi_program):
    # Create or select the stack
    stack = auto.create_or_select_stack(
        stack_name=stack_name,
        project_name=project_name,
        program=pulumi_program,
    )
    # Deploy the stack
    print("Deploying Pulumi stack...")
    up_result = stack.up()
    print(f"Deployment complete: {up_result.summary.resource_changes}")

    yield stack, up_result.outputs
