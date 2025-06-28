# Flips the sign, turns on the lights, unlocks the doors - STARTS the operation.

from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
