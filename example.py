from tinfoil import TinfoilAI

client = TinfoilAI(
    "inference.delta.tinfoil.sh",
    "tinfoilsh/provably-private-deepseek-r1",
)

chat_completion = client.chat.completions.create(
    messages=[
        {
            "role": "user",
            "content": "Hi",
        }
    ],
    model="deepseek-r1:70b",
)
print(chat_completion.choices[0].message.content)
