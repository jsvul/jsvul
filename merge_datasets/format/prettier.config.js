module.exports = {
  overrides: [
    {
      files: [
        "parse-community/parse-server/**",
        "facebook/react-native/*/Libraries/Blob/URL.js",
        "jpuri/react-draft-wysiwyg/**/index.js"
      ],
      options: {
        parser: "flow",
      },
    },
    {
      files: [
        "prahladyeri/http-live-simulator/**/bin/http-live",
        "tnantoka/public/**/bin/public"
      ],
      options: {
        parser: "babel",
      },
    },
  ],
};
