/* Copyright 2026 Rhett Creighton - Apache License 2.0 */
int main(void)
{
    *(volatile int *)0 = 1;
    return 0;
}
