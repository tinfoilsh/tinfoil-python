from tinfoil import TinfoilAI

client = TinfoilAI()

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
