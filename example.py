from tinfoil import TinfoilAI

client = TinfoilAI(
    "llama3-3-70b.model.tinfoil.sh",
    "tinfoilsh/confidential-llama3-3-70b",
)

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
