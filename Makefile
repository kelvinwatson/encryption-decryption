OBJECTS = otp_enc_d.o otp_enc.o otp_dec_d.o otp_dec.o keygen.o
EXECUTABLES = otp_enc_d otp_enc otp_dec_d otp_dec keygen

clean:
	rm -rf $(OBJECTS) $(EXECUTABLES)
