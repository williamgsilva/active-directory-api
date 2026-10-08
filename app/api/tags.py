# Tags do OpenAPI. Também definem o que cada nível de acesso enxerga na documentação.
BASIC_AUTH = "Autenticação básica"
FULL_AUTH = "Autenticação completa"
DIRECTORY = "Diretório"
TOKENS = "Tokens"
HEALTH = "Saúde"

# Escondidas da documentação para aplicações com access_level=basic
FULL_ONLY = {FULL_AUTH, DIRECTORY}
