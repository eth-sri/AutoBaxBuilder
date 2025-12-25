from agent import (
    args,
    generate_and_iterate_tests,
    generate_exploits,
    generate_scenarios,
)
from agent.cwe_lut import fetch_cwes

# from agent.verify_functional_tests import verify_tests

if __name__ == "__main__":
    if args.generate_scenarios:
        generate_scenarios()
    elif args.generate_tests:
        generate_and_iterate_tests()
        # verify_tests()
    else:
        fetch_cwes()
        generate_exploits()
