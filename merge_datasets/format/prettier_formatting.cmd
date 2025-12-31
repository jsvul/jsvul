call npm init -y
call npm i -D eslint @eslint/js @babel/core @babel/eslint-parser @babel/plugin-syntax-jsx @babel/plugin-syntax-flow @babel/plugin-proposal-function-bind @babel/plugin-proposal-decorators @babel/plugin-proposal-class-properties eslint-plugin-react eslint-plugin-react-hooks eslint-plugin-flowtype @typescript-eslint/parser @typescript-eslint/eslint-plugin typescript
call npx eslint . --fix > eslint.log 2>&1
call npm i -D prettier
call npx prettier "**/*.{js,jsx,jsm,mjs,cjs,ts,tsx}" --write --print-width 120 > prettier.log 2>&1
