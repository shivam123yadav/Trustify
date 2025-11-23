## Setup Environment Variables

1. Copy `.env.example` to a new folder called `.env`
2. Replace the placeholder values with your own secrets:
   - `API_KEY` → your API key
   - `DATABASE_URL` → your database URL(mongodb)
3. Save the `.env` file in the root of the project

## Create a virtual environment
in terminal 
>>pip install virtualenv

>>virtualenv env

now automatically env folder will be created in your project folder

## Activate virtaul environment
to run the project first you need to activate virtual environment below is the command for the same
>>.\env\Scripts\Activate.ps1

After running the above command run the project by below command
>>python app.py
