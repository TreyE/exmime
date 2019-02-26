defmodule Exmime.PemStreamWriterTest do
  use ExUnit.Case
  doctest Exmime.PemStreamWriter

  test "test overwrite a single byte" do
    f_name = "psw_stream_sb_file_and_overwrite.pkcs7"
    {:ok, out_f} = :file.open(f_name, [:binary, :read, :write])
    psw  = Exmime.PemStreamWriter.new_from_io(out_f, "PKCS7")
    initialized_psw = Exmime.PemStreamWriter.initialize(psw)
    writing_initial_psw = Exmime.PemStreamWriter.write(
      initialized_psw,
      "0123456789" <>
      "0123456789" <>
      "0123456789" <>
      "0123456789" <>
      "01234567"
    )
    {:ok, reposed_psw, _} = Exmime.PemStreamWriter.position(writing_initial_psw, 47)
    writing_done_psw = Exmime.PemStreamWriter.write(reposed_psw, "A")
    finished_psw = Exmime.PemStreamWriter.finish(writing_done_psw)

    {:ok, in_f} = :file.open(f_name, [:binary, :read])
    psr = Exmime.PemStreamReader.new_from_io(in_f)
    b64_f = Exmime.PemStreamReader.wrap_as_file(psr)
    "01234567890123456789012345678901234567890123456A" = IO.binread(b64_f, :all)
    :file.close(in_f)

    File.rm!(f_name)
  end

  test "test partial overwrite pf two adjacent tritets across lines" do
    f_name = "psw_stream_cross_file_and_overwrite.pkcs7"
    {:ok, out_f} = :file.open(f_name, [:binary, :read, :write])
    psw  = Exmime.PemStreamWriter.new_from_io(out_f, "PKCS7")
    initialized_psw = Exmime.PemStreamWriter.initialize(psw)
    writing_initial_psw = Exmime.PemStreamWriter.write(
      initialized_psw,
      "0123456789" <>
      "0123456789" <>
      "0123456789" <>
      "0123456789" <>
      "01234567891"
    )
    {:ok, reposed_psw, _} = Exmime.PemStreamWriter.position(writing_initial_psw, 47)
    writing_done_psw = Exmime.PemStreamWriter.write(reposed_psw, "ABC")
    finished_psw = Exmime.PemStreamWriter.finish(writing_done_psw)
    :file.close(out_f)

    {:ok, in_f} = :file.open(f_name, [:binary, :read])
    psr = Exmime.PemStreamReader.new_from_io(in_f)
    b64_f = Exmime.PemStreamReader.wrap_as_file(psr)
    "01234567890123456789012345678901234567890123456ABC1" = IO.binread(b64_f, :all)
    :file.close(in_f)

    File.rm!(f_name)
  end

  test "test partial overwrite of three adjacent tritets across multiple lines" do
    f_name = "psw_stream_adjacent_file_and_overwrite.pkcs7"
    {:ok, out_f} = :file.open(f_name, [:binary, :read, :write])
    psw  = Exmime.PemStreamWriter.new_from_io(out_f, "PKCS7")
    initialized_psw = Exmime.PemStreamWriter.initialize(psw)
    writing_initial_psw = Exmime.PemStreamWriter.write(
      initialized_psw,
      "0123456789" <>
      "0123456789" <>
      "0123456789" <>
      "0123456789" <>
      "0123456789" <>
      "01234567"
    )
    {:ok, reposed_psw, _} = Exmime.PemStreamWriter.position(writing_initial_psw, 47)
    writing_done_psw = Exmime.PemStreamWriter.write(reposed_psw, "ABCDEFGH")
    finished_psw = Exmime.PemStreamWriter.finish(writing_done_psw)
    :file.close(out_f)

    {:ok, in_f} = :file.open(f_name, [:binary, :read])
    psr = Exmime.PemStreamReader.new_from_io(in_f)
    b64_f = Exmime.PemStreamReader.wrap_as_file(psr)
    "01234567890123456789012345678901234567890123456ABCDEFGH567" = IO.binread(b64_f, :all)
    :file.close(in_f)

    File.rm!(f_name)
  end

  test "test partial overwrite of three adjacent tritets across multiple lines and off the end" do
    f_name = "psw_stream_off_end_file_and_overwrite.pkcs7"

    {:ok, out_f} = :file.open(f_name, [:binary, :read, :write])
    psw  = Exmime.PemStreamWriter.new_from_io(out_f, "PKCS7")
    initialized_psw = Exmime.PemStreamWriter.initialize(psw)
    writing_initial_psw = Exmime.PemStreamWriter.write(
      initialized_psw,
      "0123456789" <>
      "0123456789" <>
      "0123456789" <>
      "0123456789" <>
      "01234567891"
    )
    {:ok, reposed_psw, _} = Exmime.PemStreamWriter.position(writing_initial_psw, 47)
    writing_done_psw = Exmime.PemStreamWriter.write(reposed_psw, "ABCDEFGH")
    finished_psw = Exmime.PemStreamWriter.finish(writing_done_psw)
    :file.close(out_f)

    {:ok, in_f} = :file.open(f_name, [:binary, :read])
    psr = Exmime.PemStreamReader.new_from_io(in_f)
    b64_f = Exmime.PemStreamReader.wrap_as_file(psr)
    "01234567890123456789012345678901234567890123456ABCDEFGH" = IO.binread(b64_f, :all)
    :file.close(in_f)

    File.rm!(f_name)
  end
end
