package src.algorithms;

public class AESDebug {
	private boolean debug = true;
	
	private void setTrue(){
		debug = true;
	}
	
	private void setFalse(){
		debug = false;
	}
	
	public void print(String s){
		if(debug){
			System.out.print(s);
		}
	}
	
	public void println(String s){
		if(debug){
			System.out.println(s);
		}
	}
	
	public void println(){
		if(debug){
			System.out.println();
		}
	}
	
	public void println(int n){
		if(debug){
			System.out.println(n);
		}
	}
	
	public void println(byte b){
		if(debug){
			System.out.println(b);
		}
	}
}
