import babelParser from "@babel/eslint-parser";
import flowtype from "eslint-plugin-flowtype";
import js from "@eslint/js";
import react from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import ts from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";

export default [
  // base JS
  js.configs.recommended,

  // JS/JSX with legacy bind operator support
  {
    files: ["**/*.{js,jsx,mjs,cjs,jsm}"],
    languageOptions: {
      ecmaVersion: "latest",
      sourceType: "module",
      parser: babelParser,
      parserOptions: {
        requireConfigFile: false,
        babelOptions: {
          plugins: [
            "@babel/plugin-syntax-jsx",
            "@babel/plugin-proposal-function-bind",
            "@babel/plugin-syntax-flow",
            ["@babel/plugin-proposal-decorators", { legacy: true }],
            ["@babel/plugin-proposal-class-properties", { loose: true }],
          ],
        },
        ecmaFeatures: { jsx: true }
      }
    },
    plugins: { flowtype, react, "react-hooks": reactHooks },
    rules: {
      "react/jsx-uses-react": "off",        // not needed for React 17+
      "react/react-in-jsx-scope": "off",
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn",
      ...flowtype.configs.recommended.rules
    },
    settings: {
      react: { version: "detect" },
      flowtype: { onlyFilesWithFlowAnnotation: true }
    }
  },

  // TypeScript / TSX
  {
    files: ["**/*.ts", "**/*.tsx"],
    languageOptions: {
      parser: tsParser,
      parserOptions: { project: false, ecmaFeatures: { jsx: true } }
    },
    plugins: { "@typescript-eslint": ts, react, "react-hooks": reactHooks },
    rules: {
      ...ts.configs.recommended.rules,
      // override: disable core rule, enable TS rule
      "no-unused-vars": "off",
      "@typescript-eslint/no-unused-vars": "warn",
      "react-hooks/rules-of-hooks": "error",
      "react-hooks/exhaustive-deps": "warn"
    },
    settings: { react: { version: "detect" } }
  },

  // global rules (apply to all files)
  {
    rules: {
      "one-var": ["error", "never"],   // split `let a,b` into multiple statements
      "prefer-const": "error",
      "no-var": "error"
    }
  },

  // ignore patterns (replaces .eslintignore)
  {
    ignores: [
      "bower/bower/*/lib/util/extract.js",
      "cthackers/adm-zip/6f4dfeb9a2166e93207443879988f97d88a37cde/adm-zip.js",
      "cthackers/adm-zip/e116bc18df51e4e50c493cede82ae7696954b511/adm-zip.js",
      "dcodeio/closurecompiler.js/*/scripts/configure.js",
      "devsnd/cherrymusic/*/res/js/playlistmanager.js",
      "digitalbazaar/forge/*/js/aesCipherSuites.js",
      "francoisjacquet/rosariosis/*/assets/js/warehouse.js",
      "ibmdb/node-ibm_db/*/lib/odbc.js",
      "ibmdb/node-ibm_db/*/driverInstall.js",
      "keycloak/keycloak/*/themes/src/main/resources/theme/base/admin/resources/js/controllers/clients.js",
      "kiegroup/jbpm-designer/*/jbpm-designer-client/src/main/resources/org/jbpm/designer/public/js/Plugins/jpdlmigration.js",
      "misp/misp/*/app/webroot/js/workflows-editor/workflows-editor.js",
      "npm/npm/*/lib/npm.js",
      "omphalos/crud-file-server/*/crud-file-server.js",
      "os4ed/opensis-classic/*/js/Ajaxload.js",
      "os4ed/opensis-classic/*/js/DivControl.js",
      "phpmyadmin/phpmyadmin/57ae483bad33059a885366d5445b7e1f6f29860a/js/functions.js",
      "phpmyadmin/phpmyadmin/960fd1fd52023047a23d069178bfff7463c2cefc/js/functions.js",
      "phpmyadmin/phpmyadmin/f33a42f1da9db943a67bda7d29f7dd91957a8e7e/js/functions.js",
      "phpmyadmin/phpmyadmin/b3d36dc836df31a7d1b1c4f61f578a9b42bd1f98/js/functions.js",
	  "rendrjs/rendr/*/server/router.js",
	  "sap/less-openui5/*/lib/thirdparty/less/lessc_helper.js",
	  "theforeman/foreman/*/app/assets/javascripts/host_edit_interfaces.js",
	  "ury-erp/ury/*/ury/public/js/pos_extend.js",
	  "wp-plugins/rt-prettyphoto/*/js/jquery.prettyPhoto.js",
	  "wwbn/avideo/*/view/js/script.js",
	  "zimbra/zm-ajax/*/WebRoot/js/ajax/dwt/xforms/XFormItem.js"
    ]
  }
];
