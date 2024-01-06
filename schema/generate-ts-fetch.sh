#! /bin/zsh

docker run --rm \
  -v ${PWD}:/local openapitools/openapi-generator-cli generate \
  -i /local/openapi_by_hand.yml \
  -g typescript-fetch \
  -o /local/openapi-fetch

rm -r ../../frontend/src/lib/openapi-fetch

mv ./openapi-fetch ../../frontend/src/lib/openapi-fetch