=====
Usage
=====


To develop on hashivaultlib:

.. code-block:: bash

    # The following commands require pipenv as a dependency

    # To lint the project
    _CI/scripts/lint.py

    # To execute the testing
    _CI/scripts/test.py

    # To create a graph of the package and dependency tree
    _CI/scripts/graph.py

    # To build a package of the project under the directory "dist/"
    _CI/scripts/build.py

    # To see the package version
    _CI/scipts/tag.py

    # To bump semantic versioning [--major|--minor|--patch]
    _CI/scipts/tag.py --major|--minor|--patch

    # To upload the project to a pypi repo if user and password are properly provided
    _CI/scripts/upload.py

    # To build the documentation of the project
    _CI/scripts/document.py



To use hashivaultlib in a project:

.. code-block:: python

    from hashivaultlib import Vault
    vault = Vault(url, token)

    # Recursivelly retrieve all secrets under a path
    secrets = vault.retrieve_secrets_from_path('secrets/passwords')

    # After editing the secrets they can be put back
    vault.restore_secrets(secrets)

    # Paths can also be moved to a new location.
    # Each secret has an "original_path" attribute that can be manipulated
    secrets = vault.retrieve_secrets_from_path('secrets/passwords')
    for secret in secrets:
        secret.original_location = secret.original_location.replace('old_path', 'new_path')
    vault.restore_secrets(secrets)

    # Recursivelly delete everything under a path
    vault.delete_path('secrets/path_to_delete')

    # Work with tokens
    for token in vault.tokens:
        print(token.display_name)

    # Delete all non root tokens
    for token in vault.tokens:
        if 'root' not in token.policies:
            token.delete()
