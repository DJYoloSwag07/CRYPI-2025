# Commitment database

This small project will store commitments in a blockchain-like database and validate presences.

## Install

1. Install [uv](https://docs.astral.sh/uv/)
2. `uv sync`
   *This will handle installing Python 3.13 if not present, and creating a virtual environment.*
3. `source .venv/bin/activate`
4. `cd db`
5. Create the database with `python3 manage.py migrate`
6. (Optional) Create an admin account with `python3 manage.py createsuperuser`

## Start the server

1. `source .venv/bin/activate`
2. `cd db`
3. `python3 manage.py runserver`

## Managing commitments

### Creating a commitment

Create a commitment by sending a `PUT` request to `http://localhost:8000/<identity-hash>`

This will return 201 if an entry was created, 409 if this hash was already registered.

### Verifying a commitment

Verify the existence of a commitment by sending a `GET` request to `http://localhost:8000/<identity-hash>`

This will return 200 if the entry exists, 404 if it does not.

### Viewing commitments

Open http://localhost:8000/admin to open the Django admin panel, and log in with the credentials
chosen during installation. This will allow you to browse the list of commitments.

### Verifying the blockchain integrity

The integrity verification is not done automatically. To check that none of the entries were
tampered, run `python3 manage.py proof`

This is a blockchain-like structure, but since it only runs locally, there is no proper way to
ensure integrity.
