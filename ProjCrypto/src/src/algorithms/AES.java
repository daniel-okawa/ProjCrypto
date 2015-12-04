package src.algorithms;

import org.bouncycastle.util.Arrays;

public class AES {
	
	private int keySize = 128;
	private int Nb = 4;
	private int Nk = keySize / 32;
	private int Nr = Nk + 6;
	
	private byte[] inputArray = new byte[4 * Nb];
	private byte[] outputArray = new byte[4 * Nb];
	private byte[] word = new byte [Nb * (Nr + 1)];
	private byte[] stateArray = new byte[4 * Nb];
	
	private AESDebug debug = new AESDebug();
	
	public AES(String mode){
		if (mode == "ECB"){
			
		}
		else if (mode == "CBC"){
			
		}
		else if (mode == "CTR"){
			
		}
	}
	
	public void interfaceAES(){
		aes_encrypt();
	}
	
	private void aes_encrypt(){
		//Copia a input para o state
		byte[] testArray = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 };
		inputArray = testArray.clone();
		stateArray = inputArray.clone();
		//addRoundKey(stateArray, word[0][Nb - 1]);
		
		/*for (int round = 1; round < Nr -1; round++){
			subBytes(stateArray);
			shiftRows(stateArray);
			mixColumns(stateArray);
			addRoundKey(stateArray, word[round * Nb][(round + 1) * Nb - 1]);
		}
		
		subBytes(stateArray);
		shiftRows(stateArray);
		addRoundKey(stateArray, word[Nr * Nr][(Nr + 1) * Nb - 1]);*/
		
		shiftRows(stateArray);
		outputArray = stateArray.clone();
		System.out.println("Output: " + outputArray);
	}
	
	private void subBytes(byte[] stateArray){}
	
	private void shiftRows(byte[] stateArray){
		byte[] temp = stateArray;
		int j = 0;
		for(int i = 1; i < Nb; i++){
			temp[4 * j + i] = stateArray[4 * (j + i)];
			for(j = 0; j < 4; j++){
				stateArray[4 * j + i] = stateArray[(4 * j + i) + 4];
			}
			stateArray[j] = temp[j];
		}
	}
	
	private void mixColumns(byte[] stateArray){
		
	}
	
	private void subWord(byte[] temp){}
	
	/*private void keyExpansion(byte[] key, byte[] word){
		byte[] temp;
		int i;
		for(i = 0; i < Nb; i++){
			for(int j = 0; j < Nk; j++){
				word[4 * i + j] = key[j];
			}
		}
		
		i = Nk;
		
		while (i < Nb * (Nr + 1)){
			temp = Arrays.copyOfRange(word, 0, i - 1);
			if (i % Nk == 0){
				temp = subWord(rotWord(temp)) ^ rCon[i / Nk];
			}
			else if (Nk > 6 && i % Nk == 4){
				temp = subWord(temp);
			}
			i++;
		}
	}*/
	
	private void addRoundKey(byte[] stateArray, byte word){
		int i = 0;
		for (byte b : stateArray){
		    stateArray[i] = (byte) (b^ word);
			System.out.println(stateArray[i]);
		}
	}
	
	private void printArray(byte[] array){
		for(int i = 0; i < 4; i++){
			for(int j = 0; j < Nb; j++){
				debug.print(array[4 * i + j] + " ");
			}
			debug.println();
		}
	}
}
