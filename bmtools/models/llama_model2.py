#!/usr/bin/env python
# coding=utf-8
from langchain.llms import LlamaCpp
from langchain import PromptTemplate, LLMChain
from langchain.callbacks.streaming_stdout import StreamingStdOutCallbackHandler

    
if __name__ == "__main__":
    # can accept all huggingface LlamaModel family
    # Make sure the model path is correct for your system!
    llm = LlamaCpp(
        model_path="/home/nzinfo/llama2/llama-2-7b-chat.ggmlv3.q8_0.bin",
        temperature=0.75,
        max_tokens=2000,
        top_p=1,
        verbose=True,
    )
    # llm = LlamaCpp(model_path="/home/nzinfo/llama2/llama-2-7b-chat.ggmlv3.q8_0.bin", temperature=0.75, max_tokens=4096, top_p=1, verbose=True )
    print(llm("You are an task creation AI that uses the result of an execution agent to create new tasks with the following objective: What's the weather in Shanghai today? Should I bring an umbrella?, The last completed task has the result: According to the weather report, it is sunny in Shanghai today and there is no precipitation, so you do not need to bring an umbrella.. This result was based on this task description: Make a todo list about this objective: What's the weather in Shanghai today? Should I bring an umbrella?. These are incomplete tasks: . Based on the result, create new tasks to be completed by the AI system that do not overlap with incomplete tasks. Do not generate repetitive tasks (e.g., tasks that have already been completed). If there is not futher task needed to complete the objective, only return NO TASK. Now return the tasks as an array."))