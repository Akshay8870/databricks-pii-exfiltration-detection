# =====================================================================
# create_serving_endpoint.py
# Path A helper: create a Databricks *external model* serving endpoint that
# fronts an Azure AI Foundry (Azure OpenAI) chat deployment. Run this in a
# Databricks notebook (Runtime 13.0 ML+), or locally with the Databricks CLI
# auth configured.
#
#   %pip install "mlflow[genai]>=2.9.0"
#
# Prereq: the Foundry API key is stored as a Databricks secret:
#   databricks secrets create-scope foundry
#   databricks secrets put-secret foundry api_key
#
# After this runs, query it from SQL with:
#   SELECT ai_query('pii-dlp-judge', 'Reply with the single word OK.');
# =====================================================================

import mlflow.deployments

# ---- edit these four values -----------------------------------------
ENDPOINT_NAME   = "pii-dlp-judge"                                   # used in ai_query()
FOUNDRY_BASE    = "https://<your-resource>.openai.azure.com"        # from Foundry (no trailing /)
DEPLOYMENT_NAME = "pii-dlp-judge"                                   # the model deployment name in Foundry
API_VERSION     = "2024-10-21"                                      # your resource's api version
MODEL_NAME      = "gpt-4o-mini"                                     # the deployed model
SECRET_REF      = "{{secrets/foundry/api_key}}"                     # Databricks secret holding the key
# ---------------------------------------------------------------------

client = mlflow.deployments.get_deploy_client("databricks")

config = {
    "served_entities": [{
        "name": ENDPOINT_NAME,
        "external_model": {
            "name": MODEL_NAME,
            "provider": "openai",
            "task": "llm/v1/chat",
            "openai_config": {
                "openai_api_type": "azure",
                "openai_api_key": SECRET_REF,
                "openai_api_base": FOUNDRY_BASE,
                "openai_deployment_name": DEPLOYMENT_NAME,
                "openai_api_version": API_VERSION,
            },
        },
    }]
}

# Create, or update if it already exists.
try:
    ep = client.create_endpoint(name=ENDPOINT_NAME, config=config)
    print("Created endpoint:", ep.get("name", ENDPOINT_NAME))
except Exception as exc:
    print("Create failed (updating instead):", exc)
    ep = client.update_endpoint(endpoint=ENDPOINT_NAME, config=config)
    print("Updated endpoint:", ENDPOINT_NAME)

# Smoke test
resp = client.predict(
    endpoint=ENDPOINT_NAME,
    inputs={"messages": [{"role": "user", "content": "Reply with the single word OK."}],
            "temperature": 0, "max_tokens": 5},
)
print("Smoke test response:", resp)
