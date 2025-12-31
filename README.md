# JsVul

JsVul is a Python library to generate a function level JavaScript vulnerability database.

## Requirements

 - Node.js installed (tested with v24)
 - Python installed (tested with 3.13)

## Installation

If you want to run the merge or process steps, create a .env file in the root folder based on the .env.sample file:
- for the merge step, you need API tokens to increase rate limits:
  - create a github token with repo access and add it as GH_TOKEN
  - create an NVD API key and add it as NVD_API_KEY
- for the process step, you need to set the paths of the to two helper tools:
  - Clone [js-minify-helper](https://github.com/jsvul/js-minify-helper), run "npm i" in it's folder, and set JSMH_PATH like in .env.sample
  - Clone [js-function-extractor](https://github.com/jsvul/js-function-extractor), run "npm i" in it's folder, and set JSFE_PATH

THen install the required Python packages:

```bash
pip install -r requirements.txt
```

## Usage

You can simply run the tool with default settings by executing:

```bash
python tool.py
```

You can also download the result of the merge step [from here](https://jsvul.github.io/jsvul-database.json) and place it under the `_data` folder, then run only the process and unify steps.

Or you can download the result of the process step [from here](https://jsvul.github.io/jsvul-processed-database.json) and place it under the `_data` folder, then run only the unify step.

Our version of the unified result data with **80-10-10 train-validation-test split** can be found [here](https://jsvul.github.io/jsvul-unified-database.json).

Our version of the unified result data with **only paired examples** and **80-10-10 train-validation-test split** can be found [here](https://jsvul.github.io/jsvul-unified-database.json).

## Contributing

Pull requests are welcome. For major changes, please open an issue first
to discuss what you would like to change.

## License

[GNU GPLv3](https://choosealicense.com/licenses/gpl-3.0/)