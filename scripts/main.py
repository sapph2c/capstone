from openai import OpenAI
from dotenv import load_dotenv
from os import getenv


def main():
    load_dotenv()
    api_key = getenv("API_KEY")
    base_url = "https://api.deepseek.com"
    client = OpenAI(
        base_url=base_url,
        api_key=api_key,
    )

    file_path = "base_malware.c"

    with open(file_path, "r") as file:
        c_program_content = file.read()

    user_prompt = f"insert here your base prompt. Below it will be the base malware we just read in\n\n{c_program_content}"

    completion = client.chat.completions.create(
        model="deepseek-reasoner",
        messages=[
            {
                "role": "system",
                "content": "You are a security researcher specializing in malware development.",
            },
            {"role": "user", "content": user_prompt},
        ],
        stream=True,
        max_tokens=8000,
    )

    for chunk in completion:
        content = chunk.choices[0].delta.content
        if content:  # Ensure content is not None
            print(content, end="", flush=True)


if __name__ == "__main__":
    main()

