from tinfoil import TinfoilAI

client = TinfoilAI()

chat_completion = client.chat.completions.create(
    messages=[
        {
            "role": "user",
            "content": "What is Tinfoil?",
        }
    ],
    model="llama-free",
)
print(chat_completion.choices[0].message.content)
