from tinfoil import TinfoilAI

client = TinfoilAI(
    "deepseek-r1-70b-p.model.tinfoil.sh",
    "tinfoilsh/confidential-deepseek-r1-70b-prod",
)

chat_completion = client.chat.completions.create(
    messages=[
        {
            "role": "user",
            "content": "Hi",
        }
    ],
    model="deepseek-r1-70b",
)
print(chat_completion.choices[0].message.content)
