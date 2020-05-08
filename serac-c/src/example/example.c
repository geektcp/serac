
int sum(int num1, int num2){
    int result = num1 + num2;
    return result;
}

void sumarray(int a[], int b[], int result[], int size) {
	for (int i=0; i<size; i++) {
		result[i] = a[i] + b[i];
	}
}
