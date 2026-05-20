from agent.config import initialize_config

# from agent.verify_functional_tests import verify_tests

if __name__ == "__main__":
    args = initialize_config()

    if args.generate_scenarios:
        from agent.generate_scenarios import generate_scenarios

        generate_scenarios()
    elif args.generate_tests:
        from agent.functional_tests import generate_and_iterate_tests

        generate_and_iterate_tests()
        # verify_tests()
    else:
        from agent.cwe_lut import fetch_cwes
        from agent.generate_exploits import generate_exploits

        fetch_cwes()
        generate_exploits()
