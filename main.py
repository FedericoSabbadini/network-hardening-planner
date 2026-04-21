from unified_planning.engines import PlanGenerationResultStatus
import json
import os
import time
from planner.conf import ACTION_COSTS
from planner.problem import NetworkHardeningProblem


def get_action_type(action_name):
    name = action_name.lower()

    if 'block_port' in name:
        return 'block_port'
    elif 'patch_service' in name:
        return 'patch_service'
    elif 'migrate_service' in name:
        return 'migrate_service'
    elif 'disable_service' in name:
        return 'disable_service'
    elif 'block_for_maintenance' in name:
        return 'block_for_maintenance'
    elif 'open_new_port' in name:
        return 'open_new_port'
    elif 'restore_service' in name:
        return 'restore_service'
    return 'other'


def run_scenario(json_path):
    if not os.path.exists(json_path):
        print("Error: file not found")
        return

    with open(json_path) as f:
        scenario = json.load(f)

    name = scenario.get('scenario_name', 'scenario')

    print(f"\nScenario: {name}")

    problem = NetworkHardeningProblem(scenario)

    start = time.time()
    result, _ = problem.solve()
    elapsed = time.time() - start

    if result is None:
        print("Result: ERROR")
        return

    if result.status not in [
        PlanGenerationResultStatus.SOLVED_SATISFICING,
        PlanGenerationResultStatus.SOLVED_OPTIMALLY
    ]:
        print(f"Result: UNSOLVABLE ({elapsed:.3f}s)")
        return

    plan = [str(a) for a in result.plan.actions]

    total_cost = 0

    print("\nPlan:")
    for i, action in enumerate(plan, 1):
        print(f"{i:3d}. {action}")
        action_type = get_action_type(action)
        if action_type in ACTION_COSTS:
            total_cost += ACTION_COSTS[action_type]

    print(f"\nSolved in {elapsed:.3f}s")
    print(f"Total actions: {len(plan)}")
    print(f"Total cost: {total_cost}")

    # Save plan
    return {
        'scenario': name,
        'status': 'SOLVED',
        'elapsed_time': elapsed,
        'total_actions': len(plan),
        'total_cost': total_cost,
        'plan': plan
    }


if __name__ == "__main__":
    path = input("Enter path to JSON scenario: ").strip()
    run_scenario(path)