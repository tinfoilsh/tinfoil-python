import os

from tinfoil import create_client

client = create_client(api_key=os.environ["TINFOIL_API_KEY"])

chat_completion = client.chat.completions.create(
    messages=[
        {
            "role": "user",
            "content": "What is Tinfoil?",
        }
    ],
    model="llama3-3-70b",
)
print(chat_completion.choices[0].message.content)
