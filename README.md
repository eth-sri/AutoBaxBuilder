# AutoBaxBuilder

## Overview

We present AutoBaxBuilder, an automated framework that generates code security benchmark tasks from scratch, reducing manual effort by ~12× while matching or outperforming expert tests and exploits.

- Paper: [AutoBaxBuilder: Bootstrapping Code Security Benchmarking](https://arxiv.org/abs/2512.21132)
- Website: [baxbench.com/autobaxbuilder](https://baxbench.com/autobaxbuilder)
- Dataset: [HuggingFace](https://huggingface.co/datasets/eth-sri/autobaxbench)

## Setup

We recommend using the **Docker-based workflow** for reproducibility. A native Conda-based setup is also provided for convenience.

### Option 1: Docker

Build the Docker image, ensuring user and Docker group IDs are aligned with the host for reproducibility and correct permissions:

```bash
docker build \
  --build-arg UID=$(id -u) \
  --build-arg GID=$(id -g) \
  --build-arg DOCKER_GID=$(getent group docker | cut -d: -f3) \
  -t autobaxbuilder .
```

Should `getent` not exist on your system, fall back to `--build-arg DOCKER_GID=$(stat -c '%g' /var/run/docker.sock)` instead.

Load environment variables in a `.env` file:

```bash
export OPENAI_API_KEY="<your_API_key>"
export TOGETHER_API_KEY="<your_API_key>"
export ANTHROPIC_API_KEY="<your_API_key>"
export OPENROUTER_API_KEY="<your_API_key>"
```

Run an interactive shell inside the container, mounting the current directory and loading the environment variables:

```bash
docker run \
  --network host \
  --env-file /path/to/env \
  -it \
  --memory="4g" \
  --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v $(pwd):/app \
  autobaxbuilder /bin/bash
```

If `--network host` is not available in your system configuration, use `--add-host=localhost:host-gateway` instead.

### Option 2: Native (Conda)

The project uses the conda package manager. Please install it from [here](https://docs.conda.io/projects/conda/en/latest/user-guide/install/index.html). If you would like to have a lightweight installation, consider [Miniconda](https://docs.anaconda.com/miniconda/).

Then, the environment can be installed by running the following command:

```
conda env create -n autobaxbuilder -f env.yaml
```

Activate the environment:

```
conda activate autobaxbuilder
```

Then, install the module:
```
pip install -e .
```

Optional system dependencies (generally not needed, only required by some BaxBench scenarios):
- **imagemagick** - For image conversion scenarios
- **ffmpeg** - For video processing scenarios  
- **poppler-utils** - For PDF text extraction (provides `pdftotext`)
- **nodejs** - For TypeScript compilation scenarios
- **g++** and **make** - For C++ compilation scenarios

```bash
sudo apt install imagemagick ffmpeg poppler-utils nodejs g++ make
```

Optionally, set up the pre-commit hooks:

```
pre-commit install
```


## Generating New Scenarios with AutoBaxBuilder

Ensure the docker daemon is running. Then, either use the convenience script (recommended) or run the stages manually.

### Using the Convenience Script
From the repository root, `autobaxbuilder.sh` runs the full generation pipeline for one or more scenarios. Usage: `./autobaxbuilder.sh [OPTIONS]`

```bash
Options: 
  -n, --n-scenarios N    Total scenarios to generate                    (default: 1)
  -P, --parallel N       Parallel workers                               (default: 1)
  -d, --difficulty N     Number of endpoints: 1=easy 3=medium 5=hard    (default: 3)
  -p, --path PATH        Artifacts base directory                       (default: <script_dir>/artifacts)
  -v, --debug            Enable debug output                            (default: off)
```

The script generates scenarios, tests, and exploits, then copies the latest generated scenario `.py` file into the artifacts directory.

### Manually
Run AutoBaxBuilder from the repository root with `python src/main.py`. It runs in 3 modes, specified by the 3 flags:

#### Modes
- `--generate_scenarios`: Generate scenarios
- `--generate_tests`: Generate tests (requires `--scenario` parameter)
- `--generate_exploits`: Generate exploits (requires `--scenario` parameter)

#### Required Parameters
- `--scenario`: Scenario name (required when using `--generate_tests` or `--generate_exploits`)

#### Optional Parameters
- `--difficulty N`: Number of endpoints of the scenario
- `--N_RETRIES N`: Number recovery steps in agentic retry loops
- `--N_SOL_STEPS N`: Maximum steps for solution iteration
- `--N_TEST_STEPS N`: Maximum steps for test iteration
- `--N_SEC_STEPS N`: Maximum steps for security iteration
- `--debug`: Debug mode (print additional information)
- `--path PATH`: Artifact path

#### Examples
```bash
# Generate scenarios
python src/main.py --generate_scenarios

# Generate tests for a specific scenario
python src/main.py --generate_tests --scenario FooBarScenario

# Generate exploits for a specific scenario
python src/main.py --generate_exploits --scenario FooBarScenario

# Run in debug mode
python src/main.py --generate_tests --debug

# Save artifacts in a different directory
python src/main.py --generate_scenarios --path /path/to/artifacts/
```

#### Artifact Overview
`--generate_scenarios` produces a new folder in the artifacts directory, corresponding to a novel scenario. `--generate_tests` takes the scenario name of a scenario produced with `--generate_scenarios`, on the basis of which it generates functional tests. `--generate_exploits` also takes a scenario name and builds on top of the previous steps to develop security tests. In each step, artifacts are created. For an exemplary scenario named `FooBarScenario`, these are structured as follows:
- `FooBarScenario.json`: Initial scenario specification from `--generate_scenarios`
- `FooBarScenario_iu{t}`: Scenario specification (JSON and Py) after t steps of test iteration
- `FooBarScenario_iw{t}`: Scenario specification (JSON and Py) after t steps of security iteration
- `FooBarScenario_implementations_it{t}`: Solutions after t steps of solution iteration
- `FooBarScenario_implementations_iu{t}`: Solutions after t steps of test iteration
- `FooBarScenario_implementations_iw{t}`: Solutions after t steps of security iteration
- `FooBarScenario_results_{it/iu/iw}{t}`: Results (JSON and iteration matrix as png) of running the tests against the solutions in each intermediate step.
- `FooBarScenario_tasklist.json`: Stored solution code paths (implementation detail)
- `token_usage.txt` and `verdicts.txt`: Diagnostic logs

### Evaluating Generated Scenarios

The `.py` artifacts the pipeline produces can directly be used as novel scenarios in the BaxBench framework. Refer to the instructions in the evaluation section below on how to generate, test and evaluate solutions for a scenario.

## Evaluating AutoBaxBuilder

The AutoBaxBench scenarios are included with and without CWE-400 in `src/scenarios/with_cwe_400` and `src/scenarios/without_cwe_400` respectively. The scenarios of our alternative model ablation are in `src/scenarios/alt_model_ablation`. When generating your own scenarios, these are stored in the `artifacts/` directory by default. The latest artifact is the latest `artifacts/scenario_name/*_iw*.py` file. To run BaxBench with these scenarios and reproduce our evaluation results, follow the following steps.

### 1. Clone the BaxBench Repository

```bash
git clone git@github.com:logic-star-ai/baxbench.git
cd baxbench
```

### 2. Set Up BaxBench Environment

Follow the setup instructions in the [BaxBench repository](https://github.com/logic-star-ai/baxbench) to install dependencies and configure the environment. Alternatively, you can simply use the AutoBaxBuilder conda or docker setup from above, which already includes all required dependencies.

### 3. Copy AutoBaxBuilder Scenario Files

Copy the scenario files from AutoBaxBuilder to the BaxBench scenarios directory, adjusting paths as needed:

```bash
# Copy AutoBaxBuilder generated scenario artifact
cp "$(ls -v /path/to/autobaxbuilder/artifacts/scenario_name/*_iw*.py | tail -n 1)" /path/to/baxbench/src/scenarios/

# Copy AutoBaxBench scenario artifact
cp /path/to/autobaxbuilder/src/scenarios/without_cwe_400/scenario_name.py /path/to/baxbench/src/scenarios/
```

### 4. Register Scenarios in BaxBench

Update the `src/scenarios/__init__.py` file in BaxBench to include the new scenario(s). Add import statements for each scenario you copied and include it in the `all_scenarios` variable.

### 5. Run BaxBench Evaluation

Now you can run the full BaxBench evaluation pipeline on the generated scenarios:

```bash
# Generate solutions for a scenario
python src/main.py \
  --models gpt-4o \
  --mode generate \
  --scenarios scenario_name

# Test the generated solutions
python src/main.py \
  --models gpt-4o \
  --mode test \
  --scenarios scenario_name

# Evaluate the results
python src/main.py \
  --models gpt-4o \
  --mode evaluate \
  --scenarios scenario_name
```

Refer to the [BaxBench repository](https://github.com/logic-star-ai/baxbench) for more details on how to generate, test, and evaluate solutions for scenarios.

## Citation

If you find AutoBaxBuilder to be helpful in your research, please use the following citation

```bibtex
@article{vonarx2025autobaxbuilderbootstrappingcodesecurity,
      title={AutoBaxBuilder: Bootstrapping Code Security Benchmarking}, 
      author={Tobias von Arx and Niels Mündler and Mark Vero and Maximilian Baader and Martin Vechev},
      year={2025},
      eprint={2512.21132},
      archivePrefix={arXiv},
}
```

## License

MIT.
