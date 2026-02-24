# get_thread_id.py
from telegram import Update
from telegram.ext import Application, MessageHandler, filters
import os

async def get_message_info(update: Update, context):
    if update.message:
        print(f"Chat ID: {update.message.chat_id}")
        print(f"Message Thread ID: {update.message.message_thread_id}")
        print(f"Message ID: {update.message.message_id}")

def main():
    token = os.getenv('TELEGRAM_BOT_TOKEN')
    app = Application.builder().token(token).build()
    app.add_handler(MessageHandler(filters.ALL, get_message_info))
    print("Bot rodando... Envie uma mensagem no tópico!")
    app.run_polling()

if __name__ == '__main__':
    main()